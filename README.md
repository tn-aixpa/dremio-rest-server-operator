# Dremio REST Server Operator

![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/tn-aixpa/dremio-rest-server-operator/release.yaml?event=release) [![license](https://img.shields.io/badge/license-Apache%202.0-blue)](https://github.com/tn-aixpa/dremio-rest-server-operator/LICENSE) ![GitHub Release](https://img.shields.io/github/v/release/tn-aixpa/dremio-rest-server-operator)
![Status](https://img.shields.io/badge/status-stable-gold)

A Kubernetes operator to start instances of [Dremio REST server](https://github.com/scc-digitalhub/dremio-rest-server), that is, some Dremio REST Server custom resources.

Explore the full documentation at the [link](https://scc-digitalhub.github.io/docs/).

## Quick start

There is an available deployment file ready to be used. You can use it to install the operator and the CRD in your Kubernetes environment:

```sh
kubectl apply -f deployment.yaml
```

An example custom resource is found at `config/samples/operator_v1_dremiorestserver.yaml`. The CRD included in the deployment file is found at `config/crd/bases/operator.dremiorestserver.com_dremiorestservers.yaml`.

To launch a CR:

```sh
kubectl apply -f config/samples/operator_v1_dremiorestserver.yaml
```

## Configuration

You can start from the provided "deployment.yaml" file and tailor it to your needs, e.g. modifying the resources that will be provided to CR containers.

### Custom Resource Properties

The CR properties are:

- `tables`: **Required**. Comma-separated list of tables to expose
- `connection`:
  - `host`: **Required**.
  - `port`: *Optional*.
  - `user`: Used with `password` to authenticate on Dremio. Do not provide if `secretName` is provided.
  - `password`: Used with `user` to authenticate on Dremio. Do not provide if `secretName` is provided.
  - `jdbcProperties`: *Optional*. String for extra connection parameters, in the format `parameter1=value&parameter2=value`.
  - `secretName`: Name of a Kubernetes secret containing authentication properties.

Note that you must provide either `secretName`, or `user` and `password`, but if you provide the former, do not provide the latter two, and vice versa.

Here is a sample file you can apply with `kubectl apply -f secret-file.yml` to create the secret:

``` yaml
apiVersion: v1
kind: Secret
metadata:
  name: mysecret
  namespace: dremio-rest-server-operator-system
stringData:
  USER: dremio
  PASSWORD: dremio123
```

A valid sample CR spec configuration is:

``` yaml
...
spec:
  tables: postgres.myschema.mytable
  connection:
    host: 192.168.123.123
    user: dremio
    password: dremio123
```

Another valid sample:

``` yaml
...
spec:
  tables: postgres.myschema.mytable
  connection:
    host: 192.168.123.123
    port: 32010
    jdbcProperties: useEncryption=false&disableCertificateVerification=true
    secretName: mysecret
```

## Development

The operator is developed with [Operator-SDK](https://sdk.operatorframework.io). Refer to its documentation and [tutorial](https://sdk.operatorframework.io/docs/building-operators/golang/tutorial/) for development details and commands. The [project layout](https://sdk.operatorframework.io/docs/overview/project-layout/) is also described there.

See CONTRIBUTING for contribution instructions.

## Security Policy

The current release is the supported version. Security fixes are released together with all other fixes in each new release.

If you discover a security vulnerability in this project, please do not open a public issue.

Instead, report it privately by emailing us at digitalhub@fbk.eu. Include as much detail as possible to help us understand and address the issue quickly and responsibly.

## Contributing

To report a bug or request a feature, please first check the existing issues to avoid duplicates. If none exist, open a new issue with a clear title and a detailed description, including any steps to reproduce if it's a bug.

To contribute code, start by forking the repository. Clone your fork locally and create a new branch for your changes. Make sure your commits follow the [Conventional Commits v1.0](https://www.conventionalcommits.org/en/v1.0.0/) specification to keep history readable and consistent.

Once your changes are ready, push your branch to your fork and open a pull request against the main branch. Be sure to include a summary of what you changed and why. If your pull request addresses an issue, mention it in the description (e.g., “Closes #123”).

Please note that new contributors may be asked to sign a Contributor License Agreement (CLA) before their pull requests can be merged. This helps us ensure compliance with open source licensing standards.

We appreciate contributions and help in improving the project!

## Authors

This project is developed and maintained by **DSLab – Fondazione Bruno Kessler**, with contributions from the open source community. A complete list of contributors is available in the project’s commit history and pull requests.

For questions or inquiries, please contact: [digitalhub@fbk.eu](mailto:digitalhub@fbk.eu)

## Copyright and license

Copyright © 2025 DSLab – Fondazione Bruno Kessler and individual contributors.

This project is licensed under the Apache License, Version 2.0.
You may not use this file except in compliance with the License. Ownership of contributions remains with the original authors and is governed by the terms of the Apache 2.0 License, including the requirement to grant a license to the project.
