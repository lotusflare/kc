# Introduction
This branch will keep out of date with keycloak main branch, and we can check out a feature branch and file PR to merge into `lf-custom-feature branch` if we need to
change the keycloak source code.

We should support build keycloak base image from:
- lf-custom-branch (by default)
- temporary custom branch (for test)

If we don't change keycloak source code and just update the SPI code or theme code. We should use our 
custom base image + SPI + theme to deploy the keycloak to improve the speed of the deployment.