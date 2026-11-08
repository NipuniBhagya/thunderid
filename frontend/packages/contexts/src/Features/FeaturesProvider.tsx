// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

import type {JSX, PropsWithChildren} from 'react';
import FeaturesContext, {type FeaturesConfig} from './FeaturesContext';

/**
 * Props for the FeaturesProvider component.
 *
 * @public
 */
export interface FeaturesProviderProps extends PropsWithChildren {
  /** Which optional parts of the UI are on beneath this provider. */
  features: FeaturesConfig;
}

/**
 * Declares which optional parts of the UI the feature packages beneath it show.
 *
 * A distribution of the Console turns off what doesn't apply to it here, so no feature package has to learn
 * where it is deployed.
 *
 * @example
 * A hosted console whose admins don't run applications on a local dev server:
 * ```tsx
 * <FeaturesProvider features={{[ApplicationFeatures.DEV_SERVER_QUICK_ADD]: false}}>
 *   <Routes />
 * </FeaturesProvider>
 * ```
 *
 * @public
 */
export default function FeaturesProvider({features, children}: FeaturesProviderProps): JSX.Element {
  return <FeaturesContext.Provider value={features}>{children}</FeaturesContext.Provider>;
}
