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
    steps:
      -
        uses: actions/checkout@v3
        with:
          fetch-depth: 0
      -
        name: Set application version
        id: set_version
        uses: kvendingoldo/semver-action@v1.10
      -
        name: Generated version
        run: echo ${{ steps.set_version.outputs.version }}

      # any other steps
```
