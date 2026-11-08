// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * Whether a client is one another component signs in with, ignoring case. Such clients come from the
 * Console's runtime config (`config.client.managed_client_ids`), for example the client a Data Plane's
 * admin console uses, so changing their protocol settings here would break that component.
 *
 * @param clientId - The application's OAuth client id, if it has one.
 * @param managedClientIds - The client ids the Console's runtime config lists as managed.
 */
export default function isManagedClient(clientId: string | undefined, managedClientIds: string[] | undefined): boolean {
  if (!clientId || !managedClientIds) {
    return false;
  }
  const normalized = clientId.toUpperCase();
  return managedClientIds.some((id) => id.toUpperCase() === normalized);
}
