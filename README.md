# Open Problems — encrypted site

This repository hosts the GitHub Pages build of the Open Problems reader at
<https://comformal.github.io/openproblems-site/>.

Everything on the `gh-pages` branch is encrypted (AES-256-GCM, key derived from
a password with PBKDF2-SHA256, 600k iterations). Only the password gate and the
decrypting service worker are plaintext. Visitors need the password to read
anything.

The branch is overwritten automatically by the `deploy-site` workflow in the
private source repositories; do not edit it by hand. To lock a device, open
`…/openproblems-site/?lock`.
