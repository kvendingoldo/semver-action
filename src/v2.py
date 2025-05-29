import argparse
import os
import sys
import logging
import subprocess
import requests
import semver
import git as real_git

from git import GitCommandError


def git(*args):
    output = subprocess.check_output(["git"] + list(args)).decode().strip()
    logging.info("Git command %s produced output:\n%s\n=======", args, output)
    return output


def actions_output(version):
    if os.getenv("GITHUB_OUTPUT"):
        with open(str(os.getenv("GITHUB_OUTPUT")), mode="a", encoding="utf-8") as env:
            print(f"version={version}", file=env)


def get_config():
    logging.debug("Building config")
    config = {
        "initial_version": os.getenv("INPUT_INITIAL_VERSION", "0.0.0"),
        "primary_branch": os.getenv("INPUT_PRIMARY_BRANCH", "main"),
        "tag_prefix": {
            "candidate": os.getenv("INPUT_TAG_PREFIX_RC", "rc/"),
            "release": os.getenv("INPUT_TAG_PREFIX_RELEASE", "")
        },
        "github": {
            "url": os.getenv("GITHUB_API_URL", "https://api.github.com"),
            "repository": os.getenv("GITHUB_REPOSITORY"),
            "token": os.environ.get("INPUT_GITHUB_TOKEN")
        },
        "features": {

        },
        "auto_release_branches": os.getenv("AUTO_RELEASE_BRANCHES", "main").split(","),
    }

    logging.debug("Config has successfully built")
    return config



def create_github_release(config, tag):
    release_data = {
        "name": tag,
        "tag_name": tag,
        "draft": False,
        "prerelease": False,
        "body": "",
        "generate_release_notes": False
    }

    logging.info(f"Creating GitHub release {release_data['name']}")

    url = f"{config['github']['url']}/repos/{config['github']['repository']}/releases"

    headers = {
        "Authorization": f"Bearer {config['github']['token']}"
    }
    resp = requests.post(
        url, json=release_data, headers=headers, timeout=60
    )

    if not resp:
        print(f"text: {resp.text!r}")
        resp.raise_for_status()


def get_bump_type(commit_message):
    result = 'minor'

    #
    # major
    #
    major_bump_keywords = ['[BUMP-MAJOR]', 'bump-major', 'feat!']
    if any(keyword in commit_message for keyword in major_bump_keywords):
        result = 'major'

    #
    # patch
    #
    patch_bump_keywords = ['[hotfix]', '[fix]', 'hotfix:', 'fix:']
    if any(keyword.lower() in commit_message.lower() for keyword in patch_bump_keywords):
        result = 'patch'

    logging.info(f'Based on the commit message {commit_message} {result} bump is required')
    return result


def get_semver_version(config, git_tag=None):
    if git_tag is None:
        return semver.VersionInfo.parse(config["initial_version"])

    git_tag_without_prefixes = git_tag
    for tag_prefix in config["tag_prefix"]:
        git_tag_without_prefixes.replace(tag_prefix, "")

    return semver.VersionInfo.parse(git_tag_without_prefixes)


def get_new_semver_version(config, tag_last, bump_type):
    version = get_semver_version(config, tag_last)

    if bump_type == 'patch':
        return version.bump_patch()
    if bump_type == 'minor':
        return version.bump_minor()  # patch is reset automatically
    if bump_type == 'major':
        return version.bump_major()  # patch and minor are reset automatically


# def get_new_version(active_branch, commit_message, tag_head, tag_last):
#     print(active_branch)
#     print(commit_message)
#     print(tag_last)
#     print(tag_head)
#
#     if tag_head is not None:
#         return None
#
#     if active_branch == "main":
#         bump_type = get_bump_type(commit_message)
#         version = get_semver_version(tag_last)
#         bumped_version = get_bumped_version(version, bump_type)
#         print(bump_type)
#         print(version)
#         print(bumped_version)
#         # Get version tag_last
#
#     # bump_type = get_bump_type(base_version, branch, commit_message, last_tag, tag_for_head)
#     # if bump_type == 'patch':
#     #     return base_version.bump_patch()
#     # if bump_type == 'minor':
#     #     return base_version.bump_minor()  # patch is reset automatically
#     # if bump_type == 'major':
#     #     return base_version.bump_major()  # patch and minor are reset automatically
#     # logging.info('No bump requested returning original version %s', base_version)
#     # return base_version
#     return ''


def create_release_branch(repo, new_version):
    release_branch = 'release/{branch_tag}'.format(branch_tag='.'.join(map(str, new_version[0:2])))
    try:
        repo.git.checkout('-b', release_branch)
        logging.info("Release branch %s successfully created", release_branch)
        repo.git.push('-u', 'origin', release_branch)
        logging.info("Release branch %s successfully pushed", release_branch)
    except Exception as ex:
        logging.info("Failed to create release branch %s. Error: %s", release_branch, ex)


def push_git_tag(repo, tag):
    print("pushed")
    repo.git.tag(tag, 'HEAD')
    repo.git.push('--tags', 'origin', 'refs/tags/{tag}'.format(tag=tag))


def main():
    # %(asctime)s - %(levelname)s - %(funcName)s - %(lineno)d -
    logging.basicConfig(
        level=logging.INFO,
        format='%(levelname)s - %(message)s'
    )

    config = get_config()

    repo_path = os.getcwd()
    repo = real_git.Repo(repo_path)

    # NOTE: it's available only for git v2.35.2+
    # DETAILS:
    #  https://github.com/actions/checkout/issues/766
    #  https://github.com/actions/checkout/issues/760
    gh_workspace = os.getenv("GITHUB_WORKSPACE")
    os.system(f"git config --global --add safe.directory {gh_workspace}")

    #
    # Get Git tag (for latest available)
    #
    try:
        tag_last = repo.git.describe('--tags', '--abbrev=0', '--candidates=100')
    except GitCommandError as ex:
        logging.warning("Not found any latest available Git tag")
        logging.debug(ex)
        tag_last = None

    #
    # Get Git tag (for HEAD)
    #
    try:
        tag_head = repo.git.describe("--exact-match", "--tags", "HEAD")
    except GitCommandError as ex:
        logging.warning("Not found Git tag for HEAD")
        logging.debug(ex)
        tag_head = None

    active_branch = str(repo.active_branch)
    commit_message = repo.head.reference.commit.message

    logging.info("Gathered information")
    logging.info(f"Git branch: '{active_branch}'")
    logging.info(f"Git commit message: '{commit_message}'")
    logging.info(f"Git tag (HEAD): '{tag_head}'")
    logging.info(f"Git tag (latest available): '{tag_last}'")

    if tag_head is None:
        logging.info("There is no tag for HEAD")

    if active_branch == config["primary_branch"]:
        bump_type = get_bump_type(commit_message)

        #
        # Calculate new version
        new_semver_version = get_new_semver_version(config, tag_last, bump_type)
        new_tag = f"{config['tag_prefix']['candidate']}{str(new_semver_version)}"
        logging.info(f"New tag: {new_tag}")
        push_git_tag(repo, new_tag)

        if (active_branch in config["auto_release_branches"]) or (
            '[RELEASE]' in commit_message and active_branch == config["primary_branch"]):
            logging.info("Create new release")
            create_release_branch(repo, new_semver_version)

            #
            # Create GitHub release
            create_github_release(config, new_tag)

            #
            # Switch back, and bump version in primary branch
            repo.git.checkout(active_branch)

            new_semver_version_after_release = new_semver_version.bump_minor()
            new_tag = f"{config['tag_prefix']['candidate']}{str(new_semver_version_after_release)}"
            logging.info(f"New tag for primary branch: {new_tag}")

            repo.git.commit('--allow-empty', '-m',
                            f"[semver-action] Bump upsteam version up to {str(new_semver_version_after_release)}")
            origin = repo.remote(name='origin')
            origin.push()

            push_git_tag(repo, new_tag)

    if active_branch.startswith("release/"):
        #
        # Check that bump is not major
        bump_type = get_bump_type(commit_message)
        if bump_type == "major":
            logging.error("For release branches only minor or patch version bump is available")

        #
        # Check release version and tag version
        # TODO

        #
        # Calculate new version
        new_semver_version = get_new_semver_version(config, tag_last, bump_type)
        new_tag = f"{config['tag_prefix']['release']}{str(new_semver_version)}"
        logging.info(f"New tag: {new_tag}")
        push_git_tag(repo, new_tag)

        #
        # Create GitHub release
        create_github_release(config, new_tag)

    custom_branch = False
    if custom_branch:
        pass
        # calculate version
        # current tag + sha


if __name__ == '__main__':
    sys.exit(main())
