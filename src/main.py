#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import sys
import logging
import subprocess
import requests
import semver
import git as real_git

from git import GitCommandError

INIT_VERSION = os.getenv("INPUT_INIT_VERSION")
PRIMARY_BRANCH = os.getenv("INPUT_PRIMARY_BRANCH")
RELEASE_TAG_PREFIX = os.getenv("INPUT_RELEASE_TAG_PREFIX", "")
GITHUB_TOKEN = os.environ.get("INPUT_GITHUB_TOKEN")
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY")
GITHUB_RELEASES_URL = "https://api.github.com/repos/{repo}/releases"

if os.getenv("INPUT_ENABLE_GITHUB_RELEASES") == "true":
    ENABLE_GITHUB_RELEASES = True
else:
    ENABLE_GITHUB_RELEASES = False

if os.getenv("INPUT_ENABLE_CUSTOM_BRANCHES") == "true":
    ENABLE_CUSTOM_BRANCHES = True
else:
    ENABLE_CUSTOM_BRANCHES = False


def git(*args):
    output = subprocess.check_output(["git"] + list(args)).decode().strip()
    logging.info("Git command %s produced output:\n%s\n=======", args, output)
    return output


def git_get_latest_tag(ref='HEAD', candidates=100):
    git('fetch', '--tags')
    try:
        latest_tag = git('describe', '--tags', '--abbrev=0', '--candidates={}'.format(candidates), ref)
    except subprocess.CalledProcessError as sub_ex:
        if sub_ex.returncode == 128 and not sub_ex.output:
            logging.warning('Could not detect latest tag. Returning None')
            return None
        raise sub_ex
    return latest_tag


def get_base_version(ref='HEAD'):
    latest_tag = git_get_latest_tag(ref, 100)
    logging.debug("Read latest upstream tag: %s", latest_tag)

    if latest_tag:
        latest_base_version = semver.VersionInfo.parse(latest_tag.replace(RELEASE_TAG_PREFIX, "").split('/')[-1])
    else:
        logging.warning("Unable to get base version. Returning %s", INIT_VERSION)
        latest_base_version = semver.VersionInfo.parse(INIT_VERSION)

    logging.debug('Selected base version is %s', str(latest_base_version))
    return latest_base_version


def get_bump_type(base_version, commit_branch, commit_message, last_tag, tag_for_head):
    res = ''

    # Bump for tag. commit branch is None when pipeline executed for tag
    if tag_for_head.startswith('rc/') and commit_branch is None:
        logging.info("Tag for HEAD already exists, no bump required {base_version}")
        return ''

    # Bump for primary branch
    if commit_branch == PRIMARY_BRANCH:
        if '[BUMP-MAJOR]' in commit_message:
            logging.info("Major bump type detected from commit message %s", commit_message)
            return 'major'
        if '[RELEASE]' in commit_message:
            logging.info("Release is detected in commit: %s", commit_message)

            if last_tag is None:
                logging.info("last_tag is None, minor bump")
                res = 'minor'
            else:
                if last_tag.startswith('rc/'):
                    logging.info("last_tag starts with rc/: %s, no bump", last_tag)
                    res = ''
                else:
                    logging.info("last_tag without rc/: %s, minor bump", last_tag)
                    res = 'minor'
            return res

        if any(keyword.lower() in commit_message.lower() for keyword in ['[hotfix]', '[fix]']):
            logging.info("Fix is detected in commit: %s", commit_message)
            return 'patch'

        patch_prefixes = ['fix/', 'hotfix/', 'HOTFIX/', 'FIX/']
        if any(commit_branch.startswith(prefix) for prefix in patch_prefixes):
            logging.info("Fix branch is detected: %s", commit_branch)
            return 'patch'

        logging.info('%s updated. Minor bump required.', commit_branch)
        return 'minor'

    # Bump for release branch
    if commit_branch is not None and commit_branch.startswith('release/'):
        if (
            base_version.patch == 0 and
            git_get_latest_tag(candidates=0) == 'rc/' + str(base_version)
        ):
            # version remains the same as in primary branch as it's the same commit
            logging.info('Release just cut from %s. No bump needed.', commit_branch)
            return ''
        if tag_for_head != '':
            return ''
        logging.info('Release branch update detected. Need to bump patch.')
        return 'patch'

    logging.info('No need for bump detected. Returning empty bump type')
    return ''


def get_bumped_version(last_tag, base_version, branch, commit_message, tag_for_head):
    bump_type = get_bump_type(base_version, branch, commit_message, last_tag, tag_for_head)
    if bump_type == 'patch':
        return base_version.bump_patch()
    if bump_type == 'minor':
        return base_version.bump_minor()  # patch is reset automatically
    if bump_type == 'major':
        return base_version.bump_major()  # patch and minor are reset automatically
    logging.info('No bump requested returning original version %s', base_version)
    return base_version


def get_versioned_tag_value(version, branch, commit_message):
    """
    Gets SemVer version and returns text value for tag
    If currently on primary branch, prepends "rc/" to version
    """
    if '[RELEASE]' in commit_message:
        res = str(version)
    else:
        if branch == PRIMARY_BRANCH:
            res = f"rc/{str(version)}"
            logging.info("Generating release tag for %s, tag: %s", branch, res)
        elif branch.startswith("release/"):
            res = str(version)
            logging.info("Generating release tag for %s, tag: %s", branch, res)
        else:
            res = None
    return res


def tag_not_needed(branch):
    """
    Function checks if setting tag is not needed.
    Tag is not needed when a tag is already set on this commit.
    The only exception is when `release/` branch has just been cut
    from primary branch thus has a `rc/` tag and must be tagged with "non rc/" tag
    """
    latest_tag_on_commit = git_get_latest_tag(candidates=0)
    if latest_tag_on_commit:
        # the commit already has tag set directly on it
        if (branch.startswith('release/') and
            latest_tag_on_commit.startswith('rc/')
        ):
            # this is `release/` branch and no non-rc tag is set on this commit.
            # if non-rc tag is set it will be returned by `git describe`
            # as `git describe` sorts lightweight tags alphabetically and
            # numbers (in version) git before letters (`r` in `rc/` is letter).
            # So if commit has both `rc/` and non-rc tag, the non-rc will be returned
            return False  # new tag *is* needed
        return True  # new tag *is not* needed
    return False  # new tag *is* needed


def get_previous_release(tags, last_tag):
    logging.debug("Changelog tag list: %s", tags)

    # Remove tags created after last_tag (current tag)
    for tag in tags[:]:
        if tag != last_tag:
            del tags[0]
        else:
            break

    logging.debug("Changed changelog tag list: %s ", tags)

    # Get previous release i.e. x.y.z
    for tag in tags[1:]:
        if not last_tag.endswith('.0'):
            # Select first tag in tags which starts with X.Y from last tag
            if tag.startswith('.'.join(last_tag.split('.')[:2])):
                previous_release = tag
                break
        elif tag.startswith('rc/') or not tag.endswith('.0'):
            previous_release = tag
        else:
            previous_release = tag
            break
    # Case when project is new and we got only one tag, thus previous tag will be None
    if len(tags[1:]) == 0:
        previous_release = None

    return previous_release


def create_release_branch(repo, new_version):
    release_branch = 'release/{branch_tag}'.format(branch_tag='.'.join(map(str, new_version[0:2])))
    try:
        repo.git.checkout('-b', release_branch)
        logging.info("Release branch %s successfully created", release_branch)
        repo.git.push('-u', 'origin', release_branch)
        logging.info("Release branch %s successfully pushed", release_branch)
    except Exception as ex:
        logging.info("Failed to create release branch %s. Error: %s", release_branch, ex)


def github_auth_headers():
    """
    Get the authorization headers needed for GitHub.
    Will read the GITHUB_TOKEN environment variable.
    """
    headers = {}
    token = GITHUB_TOKEN
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def create_github_release(tag):
    release_data = {
        "name": tag,
        "tag_name": tag,
        "draft": False,
        "prerelease": False,
        "body": "",
        "generate_release_notes": False
    }

    print(f"Creating release {release_data['name']}")
    url = GITHUB_RELEASES_URL.format(repo=GITHUB_REPOSITORY)
    resp = requests.post(
        url, json=release_data, headers=github_auth_headers(), timeout=60
    )

    if not resp:
        print(f"text: {resp.text!r}")
        resp.raise_for_status()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--no-push', action='store_true')

    parsed_args = parser.parse_args()
    return parsed_args


def actions_output(version):
    safe_version = version.replace("/", "-")

    if "rc" in version:
        java_version = version.replace("rc/", "") + "-RC"
    elif "fc" in version:
        java_version = version.replace("fc/", "") + "-FC"
    else:
        java_version = version

    logging.debug("Generated version is: %s", version)
    logging.debug("Safe version is: %s", safe_version)
    logging.debug("Java version is: %s", java_version)

    if os.getenv("GITHUB_OUTPUT"):
        with open(str(os.getenv("GITHUB_OUTPUT")), mode="a", encoding="utf-8") as env:
            print(f"version={version}", file=env)
            print(f"safe_version={safe_version}", file=env)
            print(f"java_version={java_version}", file=env)


def main():
    cmd_args = parse_args()
    logging.basicConfig(level=logging.INFO)

    repo_path = os.getcwd()
    repo = real_git.Repo(repo_path)

    # NOTE: it's available only for git v2.35.2+
    # DETAILS:
    #  https://github.com/actions/checkout/issues/766
    #  https://github.com/actions/checkout/issues/760
    gh_workspace = os.getenv("GITHUB_WORKSPACE")
    os.system(f"git config --global --add safe.directory {gh_workspace}")

    try:
        last_tag = repo.git.describe('--tags', '--abbrev=0', '--candidates=100')
    except GitCommandError as ex:
        last_tag = None
        logging.info("Git command output: %s", ex)

    # here we're getting base version without any RC/FC suffixes
    base_version = get_base_version()
    current_branch = str(repo.active_branch)

    try:
        tag_for_head = repo.git.describe("--exact-match", "--tags", "HEAD")
    except Exception as ex:
        logging.error(ex)
        tag_for_head = ''

    commit_message = repo.head.reference.commit.message

    logging.info("The current branch is: %s", current_branch)
    logging.info("Latest commit message: %s", commit_message)

    if current_branch == PRIMARY_BRANCH or current_branch.startswith("release/"):
        new_version = get_bumped_version(last_tag, base_version, current_branch, commit_message, tag_for_head)
        tag = get_versioned_tag_value(new_version, current_branch, commit_message)

        logging.info("Latest upstream BASE version is: %s", base_version)
        logging.info("Latest tag value is: %s", last_tag)

        if tag_for_head:
            logging.info("Current tag for head: %s", tag_for_head)
        else:
            logging.info("There is no tag for HEAD")

        logging.info("New BASE version is: %s", new_version)
        logging.info("New tag value is: %s", tag)

        if '[RELEASE]' in commit_message and current_branch == PRIMARY_BRANCH:
            if RELEASE_TAG_PREFIX != "":
                tag = RELEASE_TAG_PREFIX + tag

            logging.info("Creating release for last tag: %s", last_tag)

            tags = repo.git.tag(sort='-creatordate').split('\n')
            previous_release = get_previous_release(tags, last_tag)

            logging.info("Previous release version is: %s", previous_release)
            logging.info("New release version is: %s", tag)
            repo.git.tag(tag, 'HEAD')

            if cmd_args.no_push:
                logging.info('Flag --no-push is set, not pushing tag and exiting')
                actions_output(tag)
                return 0
            else:
                if ENABLE_GITHUB_RELEASES:
                    create_github_release(tag)

                create_release_branch(repo, new_version)
                repo.git.checkout(current_branch)
                repo.git.push('--tags', 'origin', 'refs/tags/{tag}'.format(tag=tag))
        else:
            if tag_not_needed(current_branch):
                logging.info('Setting new tag is not needed. Commit has already tagged. Exiting.')
                actions_output(last_tag)
                return 0

            logging.info("Creating tag: %s", tag)
            repo.git.tag(tag, 'HEAD')

            if cmd_args.no_push:
                logging.info('Flag --no-push is set, not pushing tag and exiting')
                actions_output(tag)
                return 0

            repo.git.push('--tags', 'origin', 'refs/tags/{tag}'.format(tag=tag))

        actions_output(tag)
    elif ENABLE_CUSTOM_BRANCHES:
        tag = "sha/" + str(repo.head.object.hexsha[0:7])
        logging.info("Custom build version is: %s", tag)
        logging.info("It is a build for custom branch (non %s or release). Tag won't be created", PRIMARY_BRANCH)
        actions_output(tag)
    else:
        logging.info("Tag setup for branch '%s' is skipped", current_branch)


if __name__ == '__main__':
    sys.exit(main())
