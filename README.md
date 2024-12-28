# Semantic Versioning Git Auto Tag Action
A GitHub action that generates SemVer compatible tag on repository commits.

# Usage example
By default, the action will create Git version tag per commit to primary and `release/*` branches. Default format of tag: `rc/x.y.z`.
Any user can create `[RELEASE] <anything>` commit, after that action will create `release/x.y` branch.
Versions in a release branch will have a format `x.y.z`.

| Commit                                                    | version                                   | before   | after    |                                                                      Additional                                                                     |
|-----------------------------------------------------------|-------------------------------------------|----------|----------|:---------------------------------------------------------------------------------------------------------------------------------------------------:|
| [BUMP-MAJOR] in the commit header                         | increases the MAJOR version               | 0.7.0    | rc/1.0.0 |                                                                                                                                                     |
| [RELEASE] in the commit header                            | removes the prefix (rc/ in our case)      | rc/0.7.0 | 0.7.0    | the release branch will be created, like release/0.7  if the VERSIONING_ENABLE_GITLAB_RELEASES variable is set, a release will be created in GitLab |
| Without special words in the commit header                | increases MINOR version                   | rc/0.6.0 | rc/0.7.0 |                                                                                                                                                     |
| Any of [FIX] [fix] [HOTFIX] in the commit header          | increases the PATCH version               | rc/1.0.0 | rc/1.0.1 |                                                                                                                                                     |
| [BUMP-MAJOR] together with [RELEASE] in the commit header | increases the MAJOR version, make release | rc/1.0.1 | 2.0.0    |                                                                                                                                                     |

## Input variables
* `primary_branch`
  * The primary branch that will be used for setting RC tag versions
  * It's optional variable, default value is `main`

* `init_version`
  * The initial project version
  * It's optional variable, default value is `0.0.0`

* `enable_custom_branches`
  * If true, script will produce sha/x.y.z version for custom branches
  * It's optional variable, default value is `true`

* `enable_github_releases`
  * If true, GitHub releases will be created as well as Git branches. Requires github_token
  * It's optional variable, default value is `0.0.0`

* `github_token`
  * GitHub token that requires for operate under GitHub. You can use `${{ secrets.GITHUB_TOKEN }}`, check example
  * It's optional variable, empty by default

* `release_tag_prefix`
  * Prefix for Git release tags
  * It's optional variable, empty by default

## Output variables
* `version`
  * Version tag

* `safe_version`
  * Version tag without specific symbols. E.g. "/" will be replaced to "-"

* `java_version`
  * Version tag in Java format. E.g.: version rc/1.2.3 will be presented as 1.2.3-RC 

## Action example

```yaml
name: My pipeline
on:
  push:
    branches:
      - 'main'
      - 'release/**'

jobs:
  build:
    runs-on: ubuntu-20.04
    permissions:
      contents: write
    steps:
      -
        uses: actions/checkout@v3
        with:
          fetch-depth: 0
      -
        name: Set application version
        id: set_version
        uses: kvendingoldo/semver-action@v1.20.2
        with:
          primary_branch: main
          enable_github_releases: true
          release_tag_prefix: "v"
          github_token: "${{ secrets.GITHUB_TOKEN }}"
          tag_prefix: "test/"
      -
        name: Generated version
        run: echo ${{ steps.set_version.outputs.version }}

      # any other steps
```
