// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

import {Context, createContext} from 'react';

/**
 * Which optional parts of the Console's UI a host app turns on or off, keyed by the feature's name, such as
 * `applications.devServerQuickAdd`. A feature package exports the names it reads.
 *
 * A feature left out is on. Only `false` turns one off.
 *
 * @public
 */
export type FeaturesConfig = Readonly<Record<string, boolean>>;

/**
 * React context carrying which optional parts of the UI are on.
 *
 * Defaults to an empty object, so a feature package renders standalone, in a test or under a host that
 * doesn't set features, with every feature on. Read it through `useFeature` rather than directly.
 *
 * @public
 */
const FeaturesContext: Context<FeaturesConfig> = createContext<FeaturesConfig>({});

export default FeaturesContext;
