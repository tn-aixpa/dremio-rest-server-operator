# Dremio REST Server Operator

A Kubernetes operator to start instances of [Dremio REST server](https://github.com/scc-digitalhub/dremio-rest-server).

## Installation
There is an available deployment file ready to be used. Install operator and CRD:
```sh
kubectl apply -f deployment.yaml
```

An example CR is found at `config/samples/operator_v1_dremiorestserver.yaml`. The CRD included in the deployment file is found at `config/crd/bases/operator.dremiorestserver.com_dremiorestservers.yaml`.

Launch CR:
```sh
kubectl apply -f config/samples/operator_v1_dremiorestserver.yaml
```

## Dremio REST Server custom resource
The custom resource's properties are:

- `tables`: **Required**. Comma-separated list of tables to expose
- `javaOptions`: *Optional*. Corresponds to *JAVA_TOOL_OPTIONS*: on JDK 9+, `--add-opens=java.base/java.nio=ALL-UNNAMED` is required
- `containerLimits`: *Optional*. K8S resource configuration, limits resources a container can have.
  - `cpu`: *Optional*, string.
  - `memory`: *Optional*, string.
- `containerRequests`: *Optional*. K8S resource configuration, the minimum a container is guaranteed to have.
  - `cpu`: *Optional*, string.
  - `memory`: *Optional*, string.
- `connection`:
  - `host`: **Required**.
  - `port`: *Optional*.
  - `user`: Used with `password` to authenticate on Dremio. Do not provide if `secretName` is provided.
  - `password`: Used with `user` to authenticate on Dremio. Do not provide if `secretName` is provided.
  - `jdbcProperties`: *Optional*. String for extra connection parameters, in the format `parameter1=value&parameter2=value`.
  - `secretName`: Name of a Kubernetes secret containing connection properties. Do not provide if `user` and `password` are provided. More information in a later section.
 
Note that you must provide either `secretName`, or `user` and `password`, but if you provide the former, do not provide the latter two, and vice versa.

A valid sample spec configuration is:
``` yaml
...
spec:
  javaOptions: --add-opens=java.base/java.nio=ALL-UNNAMED
  tables: postgres.myschema.mytable
  connection:
    host: 192.168.123.123
    user: dremio
    password: dremio123
    containerLimits:
      cpu: 1000m
      memory: 512Mi
    containerRequests:
      cpu: 200m
      memory: 128Mi
```

Another valid sample:
``` yaml
...
spec:
  javaOptions: --add-opens=java.base/java.nio=ALL-UNNAMED
  tables: postgres.myschema.mytable
  connection:
    host: 192.168.123.123
    port: 32010
    jdbcProperties: useEncryption=false&disableCertificateVerification=true
    secretName: mysecret
```

## Using a K8S secret to authenticate

Instead of writing user and password as properties, you can provide a `connection.secretName` property, containing a string with the name of a Kubernetes secret to use to authenticate.

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
