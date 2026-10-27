# Website

This website is built using [Docusaurus](https://docusaurus.io/), a modern static website generator.

## Installation

```bash
yarn
```

## Local Development

```bash
yarn start
```

This command starts a local development server and opens up a browser window. Most changes are reflected live without having to restart the server.

## Build

```bash
yarn build
```

This command generates static content into the `build` directory and can be served using any static contents hosting service.

## Deployment

Using SSH:

```bash
USE_SSH=true yarn deploy
```

Not using SSH:

```bash
GIT_USER=<Your GitHub username> yarn deploy
```

If you are using GitHub pages for hosting, this command is a convenient way to build the website and push to the `gh-pages` branch.

## Pull Request Build Check

The **Website build check** workflow runs for every pull request targeting `main`.
It runs `npm ci` and `npm run build` when the PR changes `website/`, the build-check
workflow, or the GitHub Pages deployment workflow. It checks the proposed merge
with the base branch, uses npm caching, and cancels superseded runs for the same PR.
It does not deploy the site, use deployment secrets, or require write permissions.

For PRs without matching file changes, the **Validate website build** check reports
success with "Website build not needed" and skips Node.js setup, installation, and
the build. This lets the check be required without blocking PowerShell-only PRs.

Once the workflow is on `main`, you can also select **Actions > Website build
check > Run workflow** and choose a branch for a build-only check. Manual runs
always build the website. A successful build does not replace visual or
browser-interaction testing.

### Reproduce the CI Check Locally

CI uses npm and the committed `package-lock.json`. To reproduce its dependency
installation and build, use Node.js 20 and run these commands from `website/`:

```bash
npm ci
npm run build
```

To preview the production build locally, run `npm run serve` and open the URL
printed in the terminal. Neither building nor serving publishes the website.

The separate **Deploy to GitHub Pages** workflow builds and publishes the site
when changes are pushed to `main`. Manually running that workflow also attempts
a deployment; use **Website build check** when you only want to validate a branch.
