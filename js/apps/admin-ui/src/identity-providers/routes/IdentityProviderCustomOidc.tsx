import { lazy } from "react";
import type { Path } from "react-router-dom";
import { generateEncodedPath } from "../../utils/generateEncodedPath";
import type { AppRouteObject } from "../../routes";

export type IdentityProviderCustomOidcParams = { realm: string };

const AddOpenIdConnect = lazy(() => import("../add/AddOpenIdConnect"));

export const IdentityProviderCustomOidcRoute: AppRouteObject = {
  path: "/:realm/identity-providers/custom-oidc/add",
  element: <AddOpenIdConnect />,
  handle: {
    access: "manage-identity-providers",
    breadcrumb: (t) => t("addCustomOpenIdProvider"),
  },
};

export const toIdentityProviderCustomOidc = (
  params: IdentityProviderCustomOidcParams,
): Partial<Path> => ({
  pathname: generateEncodedPath(IdentityProviderCustomOidcRoute.path, params),
});
