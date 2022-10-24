#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import logging
import argparse
import subprocess
import semver
import git as real_git
from git import GitCommandError

INIT_VERSION = os.getenv("INPUT_INIT_VERSION")
PRIMARY_BRANCH = os.getenv("INPUT_PRIMARY_BRANCH")

if os.getenv("INPUT_ENABLE_CUSTOM_BRANCHES") == "true":
    ENABLE_CUSTOM_BRANCHES = True
else:
    ENABLE_CUSTOM_BRANCHES = False

if os.getenv("INPUT_SHA_FOR_CUSTOM_BRANCHES") == "true":
    SHA_FOR_CUSTOM_BRANCHES = True
else:
    SHA_FOR_CUSTOM_BRANCHES = False


def git(*args):
    output = subprocess.check_output(["git"] + list(args)).decode().strip()
    logging.info(f"Git command {args} produced output:\n{output}\n=======")
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
    logging.debug(f"Read latest upstream tag: {latest_tag}")

    if latest_tag:
        latest_base_version = semver.VersionInfo.parse(latest_tag.split('/')[-1])
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
            logging.info(f"Major bump type detected from commit message {commit_message}")
            return 'major'
        if '[RELEASE]' in commit_message:
            logging.info(f"Release detected in commit: {commit_message}")
            if last_tag.startswith('rc/'):
                logging.info(f"last_tag starts with rc/: {last_tag}, no bump")
                res = ''
            else:
                logging.info(f"last_tag without rc/: {last_tag}, minor bump")
                res = 'minor'
            return res

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

    # Bump for custom branch
    if commit_branch is not None and ENABLE_CUSTOM_BRANCHES:
        if '[BUMP-MAJOR]' in commit_message:
            logging.info(f"Major bump type detected from commit message {commit_message}")
            return 'major'

        logging.info('%s updated. Minor bump required.', commit_branch)
        return 'minor'

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
        elif ENABLE_CUSTOM_BRANCHES:
            res = f"fc/{str(version)}"
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
    release_branch = 'release/{branch_tag}'.format(branch_tag='.'. \
                                                   join(map(str, new_version[0:2])))
    try:
        repo.git.checkout('-b', release_branch)
        logging.info(f"Release branch {release_branch} successfully created")
        repo.git.push('-u', 'origin', release_branch)
        logging.info(f"Release branch {release_branch} successfully pushed")
    except Exception as err:
        logging.info(f"Failed to create release branch {release_branch}. Error: {err}")


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

    logging.debug(f"Generated version is: {version}")
    logging.debug(f"Safe version is: {safe_version}")
    logging.debug(f"Java version is: {java_version}")

    if os.getenv("GITHUB_OUTPUT"):
        with open(str(os.getenv("GITHUB_OUTPUT")), "a") as env:
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
    gh_workspace=os.getenv("GITHUB_WORKSPACE")
    os.system(f"git config --global --add safe.directory {gh_workspace}")

    try:
        last_tag = repo.git.describe('--tags', '--abbrev=0', '--candidates=100')
    except GitCommandError as e:
        last_tag = None
        logging.info(f"Git command output: {e}")

    # here we're getting base version without any RC/FC suffixes
    base_version = get_base_version()
    current_branch = str(repo.active_branch)

    try:
        tag_for_head = repo.git.describe("--exact-match", "--tags", "HEAD")
    except Exception:
        tag_for_head = ''

    commit_message = repo.head.reference.commit.message

    logging.info(f"The current branch is: {current_branch}")
    logging.info(f"Latest commit message: {commit_message}")

    if SHA_FOR_CUSTOM_BRANCHES:
        tag = "sha/" + str(repo.head.object.hexsha[0:7])
        logging.info(f"Custom build version is: {tag}")
    else:
        new_version = get_bumped_version(last_tag, base_version, current_branch, commit_message, tag_for_head)
        tag = get_versioned_tag_value(new_version, current_branch, commit_message)

        logging.info(f"Latest upstream BASE version is: {base_version}")
        logging.info(f"Latest tag value is: {last_tag}")

        if tag_for_head:
            logging.info(f"Current tag for head: {tag_for_head}")
        else:
            logging.info("There is no tag for HEAD")

        logging.info(f"New BASE version is: {new_version}")
        logging.info(f"New tag value is: {tag}")

    if current_branch == PRIMARY_BRANCH or current_branch.startswith("release/"):
        if '[RELEASE]' in commit_message and current_branch == PRIMARY_BRANCH:
            logging.info(f"Creating release for last tag: {last_tag}")

            tags = repo.git.tag(sort='-creatordate').split('\n')
            previous_release = get_previous_release(tags, last_tag)

            logging.info(f"Previous release version is: {previous_release}")
            logging.info(f"New release version is: {tag}")
            repo.git.tag(tag, 'HEAD')

            if cmd_args.no_push:
                logging.info('Flag --no-push is set, not pushing tag and exiting')
                actions_output(tag)
                return 0
            else:
                create_release_branch(repo, new_version)
                repo.git.checkout(current_branch)
                repo.git.push('--tags', 'origin', 'refs/tags/{tag}'.format(tag=tag))
        else:
            if tag_not_needed(current_branch):
                logging.info('Setting new tag is not needed. Commit has already tagged. Exiting.')
                actions_output(last_tag)
                return 0

            logging.info(f"Creating tag: {tag}")
            repo.git.tag(tag, 'HEAD')

            if cmd_args.no_push:
                logging.info('Flag --no-push is set, not pushing tag and exiting')
                actions_output(tag)
                return 0

            repo.git.push('--tags', 'origin', 'refs/tags/{tag}'.format(tag=tag))

        actions_output(tag)

    else:
        if ENABLE_CUSTOM_BRANCHES:
            logging.info(f"It is a build for custom branch (non {PRIMARY_BRANCH} or release). Tag won't be created")
            actions_output(tag)
        else:
            logging.info("Tag setup for branch '%s' is skipped", current_branch)


if __name__ == '__main__':
    sys.exit(main())
