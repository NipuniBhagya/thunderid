// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

import {act} from 'react';
import {createRoot, type Root} from 'react-dom/client';
import {beforeEach, afterEach, describe, expect, it} from 'vitest';
import FeaturesProvider from '../FeaturesProvider';
import useFeature from '../useFeature';

function DevServerHint() {
  return useFeature('applications.devServerQuickAdd') ? <p>Dev server</p> : null;
}

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => {
    root.unmount();
  });
  container.remove();
});

describe('FeaturesProvider', () => {
  it('turns a feature off when the provider sets it to false', () => {
    act(() => {
      root.render(
        <FeaturesProvider features={{'applications.devServerQuickAdd': false}}>
          <DevServerHint />
        </FeaturesProvider>,
      );
    });

    expect(container.querySelector('p')).toBeNull();
  });

  it('keeps a feature on when the provider sets it to true', () => {
    act(() => {
      root.render(
        <FeaturesProvider features={{'applications.devServerQuickAdd': true}}>
          <DevServerHint />
        </FeaturesProvider>,
      );
    });

    expect(container.querySelector('p')?.textContent).toBe('Dev server');
  });

  it('keeps a feature on when the provider does not name it', () => {
    act(() => {
      root.render(
        <FeaturesProvider features={{'applications.other': false}}>
          <DevServerHint />
        </FeaturesProvider>,
      );
    });

    expect(container.querySelector('p')?.textContent).toBe('Dev server');
  });

  it('keeps every feature on when rendered without a provider', () => {
    act(() => {
      root.render(<DevServerHint />);
    });

    expect(container.querySelector('p')?.textContent).toBe('Dev server');
  });
});
