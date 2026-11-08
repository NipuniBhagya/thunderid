// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * Names of the optional parts of the applications UI that a host app can turn off through a
 * `FeaturesProvider`. Each is on unless the provider sets it to `false`.
 */
const ApplicationFeatures = {
  /**
   * The creation wizard's offer to add the template's local dev server URL, such as
   * `http://localhost:5173` for Vite, to the redirect URIs and CORS origins.
   */
  DEV_SERVER_QUICK_ADD: 'applications.devServerQuickAdd',
} as const;

export default ApplicationFeatures;
