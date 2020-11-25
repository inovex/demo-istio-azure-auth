# Transparent User Auth with Istio and Azure AD

This demo repository showcases how to use Istio and Azure Active Directory to transparently augment an authentication-unaware application with OAuth2 authentication.

## Prerequisites

* An setup AKS cluster

```sh
export AZURE_RESOURCE_GROUP="istio-aks-azuread"
export CLUSTER_NAME="aks-azuread"
az aks create -g $AZURE_RESOURCE_GROUP -n $CLUSTER_NAME --node-count=1
```

* `kubectl` with a kubeconfig pointing to the aforementioned cluster granting ClusterAdmin privileges (`az aks get-credentials -g $AZURE_RESOURCE_GROUP -n $CLUSTER_NAME`)
* istio installed (`istioctl install  --set profile=demo --set meshConfig.accessLogFile="/dev/stdout"`)
* TLS cert and DNS A record for the test app.

The demo was tested with kubernetes v1.16.13 and istio v1.6.3 (client, proxies and control plane)

## Demo

Create an app registration with custom scope for usage later-on

```sh
APP_HOST=example.inovex.io
APP_ENDPOINT=https://$APP_HOST
AZ_TENANT_ID=$(az account list | jq -r '.[] | select(.isDefault) | .tenantId')
APP_PASSWORD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
APP_ID=$(az ad app create --display-name demo-app --available-to-other-tenants false --homepage=$APP_ENDPOINT --password=$APP_PASSWORD --reply-urls=${APP_ENDPOINT}/loggedin | jq -r '.appId')
az ad app update --id $APP_ID --identifier-uris "api://$APP_ID"
# adding identifier URIS should cause auto-generation of a scope
APP_SCOPE="api://${APP_ID}/$(az ad app show --id $APP_ID | jq -r '.oauth2Permissions[0].value')"
# here will be relevant again
cat <<EOF >
azureTenantId: "$AZ_TENANT_ID"
azureApp:
  id: "$APP_ID"
  host: "$APP_HOST"
  clientSecret: "$APP_PASSWORD"
  scope: $APP_SCOPE
EOF
```

then render the template with the values here:

```sh
# this is not a proper chart, so we only use helm for templating in this demo
helm template -f my-values.yaml . | kubectl apply -n istio-system -f -
```

Finally, make sure your DNS Record is pointing to the IP address of the istio ingress Gateway. The IP address can be retrieved using `kubectl get service -n istio-system istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}'`

### Optional Step: Build the Cookie-Setter image

If the image is not available, or you want to make any changes, you can rebuild and use it as follows:

```sh
export IMAGE="maximilianbischoff/cookie-setter"
export TAG=$(git rev-parse HEAD)
docker build . -t ${IMAGE}:${TAG}
docker push ${IMAGE}:${TAG}

cat <<EOF > image-values.yaml
cookieSetter:
  image: "$IMAGE"
  version: "$TAG"
EOF
```

Then re-render and apply the template using `helm template -f my-values.yaml -f image-values.yaml . | kubectl apply -n istio-system -f -`.

### Optional bonus: Restrict access further using AuthorizationPolicy

```sh
kubectl apply -n istio-system -f restricted-access-policy.yaml
```

## Cleanup

```sh
az ad app delete --id $APP_ID
az aks delete -g $AZURE_RESOURCE_GROUP -n $CLUSTER_NAME
```
