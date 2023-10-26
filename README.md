# Semantic Versioning Git Auto Tag Action
A GitHub action that generates SemVer compatible tag on repository commits.

# Usage example
By default, the action will create Git version tag per commit to primary and `release/*` branches. Default format of tag: `rc/x.y.z`.
Any user can create `[RELEASE] <anything>` commit, after that action will create `release/x.y` branch.
Versions in a release branch will have a format `x.y.z`.

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
        uses: kvendingoldo/semver-action@v1.18
        with:
          enable_github_releases: true
          release_tag_prefix: "v"
          github_token: "${{ secrets.GITHUB_TOKEN }}"
      -
        name: Generated version
        run: echo ${{ steps.set_version.outputs.version }}

      # any other steps
```
