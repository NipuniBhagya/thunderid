// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

import {describe, expect, it} from 'vitest';
import isManagedClient from '../isManagedClient';

describe('isManagedClient', () => {
  it.each<[string | undefined, string[] | undefined, boolean]>([
    ['ADMIN_CONSOLE', ['ADMIN_CONSOLE'], true],
    ['admin_console', ['ADMIN_CONSOLE'], true],
    ['ADMIN_CONSOLE', ['other', 'admin_console'], true],
    ['ADMIN_CONSOLE', ['other'], false],
    ['ADMIN_CONSOLE', [], false],
    ['ADMIN_CONSOLE', undefined, false],
    [undefined, ['ADMIN_CONSOLE'], false],
    ['', [''], false],
  ])('client %s with managed clients %j is managed: %s', (clientId, managedClientIds, expected) => {
    expect(isManagedClient(clientId, managedClientIds)).toBe(expected);
  });
});
