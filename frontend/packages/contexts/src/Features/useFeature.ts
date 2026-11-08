// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

import {useContext} from 'react';
import FeaturesContext from './FeaturesContext';

/**
 * Whether the optional part of the UI named `feature` is on. True unless a `FeaturesProvider` above turns it
 * off.
 *
 * @public
 */
export default function useFeature(feature: string): boolean {
  return useContext(FeaturesContext)[feature] !== false;
}
