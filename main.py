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

DEFAULT_VERSION = '0.0.0'


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


def get_base_tag(ref='HEAD'):
    latest_tag_string = git_get_latest_tag(ref, 100)
    logging.info(f"Read latest upstream tag: {latest_tag_string}")
    if latest_tag_string:
        latest_tag_base_parsed = semver.VersionInfo.parse(latest_tag_string.split('/')[-1])
    else:
        logging.warning(f"Unable to get base version. Returning {DEFAULT_VERSION}")
        latest_tag_base_parsed = semver.VersionInfo.parse(DEFAULT_VERSION)
    logging.info('Selected base version is %s', str(latest_tag_base_parsed))
    return latest_tag_base_parsed


def get_bump_type(base_version, commit_branch, commit_message, last_tag, tag_for_head):
    res = ''

    # Bump for tag. commit branch is None when pipeline executed for tag
    if tag_for_head.startswith('rc/') and commit_branch is None:
        logging.info("Tag for HEAD already exists, no bump required {base_version}")
        return ''
    # Bump for master branch
    if commit_branch == 'master':
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

        logging.info('Master updated. minor bump required.')
        return 'minor'

    # Bump for release branch
    if commit_branch is not None and commit_branch.startswith('release/'):
        if (
                base_version.patch == 0 and
                git_get_latest_tag(candidates=0) == 'rc/' + str(base_version)
        ):
            # version remains the same as in master as it's the same commit
            logging.info('Release just cut from master. No bump needed.')
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
    If currently on `master` branch, prepends "rc/" to version
    """
    if '[RELEASE]' in commit_message:
        res = version
    else:
        if branch == 'master':
            logging.info(f"Generating release candidate tag for master rc/{version}")
            res = f"rc/{str(version)}"
        else:
            logging.info(f"Branch not master, release tag  {version}")
            res = str(version)
    return res


def tag_not_needed(branch):
    """
    Function checks if setting tag is not needed.
    Tag is not needed when a tag is already set on this commit.
    The only exception is when `release/` branch has just been cut
    from `master` thus has a `rc/` tag and must be tagged with "non rc/" tag
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


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['bump-and-tag', 'make-release'])
    parser.add_argument('--no-push', action='store_true')

    parsed_args = parser.parse_args()
    return parsed_args


def main():
    cmd_args = parse_args()
    logging.basicConfig(level=logging.INFO)
    repo_path = os.getcwd()
    repo = real_git.Repo(repo_path)

    try:
        last_tag = repo.git.describe('--tags', '--abbrev=0', '--candidates=100')
    except GitCommandError as e:
        last_tag = None
        logging.info(f"Git command output: {e}")

    base_version = get_base_tag()
    branch = repo.git.branch('--show-current')
    commit_message = repo.head.reference.commit.message

    try:
        tag_for_head = repo.git.describe("--exact-match", "--tags", "HEAD")
    except Exception:
        tag_for_head = ''
        logging.info("No tag for HEAD: %s", tag_for_head)

    new_version = get_bumped_version(last_tag, base_version, branch, commit_message, tag_for_head)
    tag_value = get_versioned_tag_value(new_version, branch, commit_message)

    logging.info(f"last_tag: {last_tag}")
    logging.info(f"base version: {base_version}")
    logging.info(f"new_version: {new_version}")
    logging.info(f"tag value: {tag_value}")
    logging.info(f"branch: {branch}")
    logging.info(f"message: {commit_message}")
    logging.info(f"tag_for_head: {tag_for_head}")

    if cmd_args.action == 'bump-and-tag':
        if tag_not_needed(branch):
            logging.info('Setting new tag is not needed. Commit already tagged. Exiting.')
            return 0

        if '[RELEASE]' in commit_message and branch == 'master':
            release = 'true'
        else:
            release = 'false'

        tag = tag_value
        logging.info(f"PERFORMING RELEASE: {release}")
        logging.info(f"Creating tag: {tag}")
        repo.git.tag(tag, 'HEAD')

        if cmd_args.no_push:
            logging.info('Flag --no-push is set, not pushing tag and exiting')
            return 0

        repo.git.push('--tags', 'origin', 'refs/tags/{tag}'. \
                      format(tag=tag))

    elif cmd_args.action == 'make-release':
        pass


if __name__ == '__main__':
    sys.exit(main())
