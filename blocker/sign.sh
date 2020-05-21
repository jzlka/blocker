#!/bin/zsh
APP="blockerd"
PATH_TO_APP=$APP
ENTITLEMENTS="${APP}.entitlements"
CERT_ID="-"

echo "\n\n**** Previous entitlements of $APP ****"
codesign -d --ent :-  "${PATH_TO_APP}/${APP}"


echo "\n\n**** Signing $APP ****"
codesign --force -vvvv --entitlements "$ENTITLEMENTS" -s "$CERT_ID" "${PATH_TO_APP}/${APP}"

echo "\n\n**** Final entitlements of $APP ****"
codesign -d --ent :-  "${PATH_TO_APP}/${APP}"
