// #1831: the theme switch is entirely a matter of ordering, and every one
// of its steps typechecks identically whether it is right or wrong.
//
// The contract: suppress transitions, change the attributes, force the new
// values to be resolved while suppression is still active, and release on
// the *second* animation frame. Releasing on the first re-enables
// transitions before the new values are painted, which is the original bug
// with extra steps — and looks correct in review.
import { act, createElement } from 'react'
import { createRoot } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const SUPPRESS_CLASS = 'hp-theme-switching'

/** Run the queued animation-frame callbacks, one frame at a time. */
function makeFrameQueue() {
  let queue: FrameRequestCallback[] = []
  const raf = ((callback: FrameRequestCallback) => {
    queue.push(callback)
    return queue.length
  }) as typeof requestAnimationFrame
  const flushOneFrame = () => {
    const due = queue
    queue = []
    due.forEach((callback) => callback(0))
  }
  return { raf, flushOneFrame, pending: () => queue.length }
}

describe('applyTheme suppression ordering', () => {
  beforeEach(() => {
    document.documentElement.className = ''
    delete document.documentElement.dataset.theme
    localStorage.clear()
    vi.resetModules()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('still suppresses transitions when applyTheme returns', async () => {
    const frames = makeFrameQueue()
    vi.stubGlobal('requestAnimationFrame', frames.raf)
    const { applyTheme } = await import('./prefs')

    applyTheme('dark')

    // The attribute is already changed, and suppression is still on: this
    // is the window in which the new values get resolved unanimated.
    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(document.documentElement.classList.contains(SUPPRESS_CLASS)).toBe(true)
  })

  it('completes the asynchronous appearance side effects', async () => {
    const { applyTheme } = await import('./prefs')
    const cssVars = await import('./cssVar')
    const resetCache = vi.spyOn(cssVars, 'resetCssVarCache')
    document.cookie = 'hp_appearance=; Max-Age=0; Path=/'
    expect(document.cookie).not.toContain('hp_appearance=')

    applyTheme('dark', { sync: false })

    await vi.waitFor(() => {
      expect(resetCache).toHaveBeenCalled()
      expect(document.cookie).toContain('hp_appearance=')
    })
    resetCache.mockRestore()
  })

  it('does not release on the first frame — that is the bug it exists to prevent', async () => {
    const frames = makeFrameQueue()
    vi.stubGlobal('requestAnimationFrame', frames.raf)
    const { applyTheme } = await import('./prefs')

    applyTheme('dark')
    frames.flushOneFrame()

    expect(document.documentElement.classList.contains(SUPPRESS_CLASS)).toBe(true)
  })

  it('releases on the second frame', async () => {
    const frames = makeFrameQueue()
    vi.stubGlobal('requestAnimationFrame', frames.raf)
    const { applyTheme } = await import('./prefs')

    applyTheme('dark')
    frames.flushOneFrame()
    frames.flushOneFrame()

    expect(document.documentElement.classList.contains(SUPPRESS_CLASS)).toBe(false)
  })

  it('releases synchronously where requestAnimationFrame does not exist', async () => {
    // Without this fallback the class is added and never removed, leaving
    // every transition in the application suppressed for the rest of the
    // session — a worse failure than the one being fixed, and one no type
    // can see.
    vi.stubGlobal('requestAnimationFrame', undefined)
    const { applyTheme } = await import('./prefs')

    applyTheme('dark')

    expect(document.documentElement.classList.contains(SUPPRESS_CLASS)).toBe(false)
    expect(document.documentElement.dataset.theme).toBe('dark')
  })

  it('clearing back to system removes the attribute rather than blanking it', async () => {
    const frames = makeFrameQueue()
    vi.stubGlobal('requestAnimationFrame', frames.raf)
    const { applyTheme } = await import('./prefs')

    applyTheme('dark')
    applyTheme('system')

    // An empty data-theme is not the same as an absent one: the stylesheet
    // distinguishes "explicitly light" from "follow the OS" by presence.
    expect('theme' in document.documentElement.dataset).toBe(false)
    expect(localStorage.getItem('hp-theme')).toBeNull()
  })
})

// #2138: appearance must follow the operator across tabs, and the only notice
// another tab receives is a `storage` event. These tests drive the real
// registration path -- mounting a subscriber to useAppearanceKey -- then play
// the other tab the way a second document does: change the key under the
// running page and dispatch. Assertions are on end state (the attributes),
// because that is where a wrong mapping shows.
describe('cross-tab storage events (#2138)', () => {
  beforeEach(() => {
    document.documentElement.className = ''
    delete document.documentElement.dataset.theme
    delete document.documentElement.dataset.hpTheme
    delete document.documentElement.dataset.hpPalette
    localStorage.clear()
    vi.resetModules()
  })

  /** Mount a minimal component so useAppearanceKey's subscribe runs. */
  async function mountSubscriber(): Promise<void> {
    const { useAppearanceKey } = await import('./prefs')
    let root: ReturnType<typeof createRoot>
    function Probe(): null {
      useAppearanceKey()
      return null
    }
    await act(async () => {
      root = createRoot(document.createElement('div'))
      root.render(createElement(Probe))
    })
  }

  /** Play the writing tab: change the key directly, then notify. */
  async function writeAsOtherTab(key: string | null, newValue: string | null): Promise<void> {
    if (key === null) {
      localStorage.clear()
    } else if (newValue === null) {
      localStorage.removeItem(key)
    } else {
      localStorage.setItem(key, newValue)
    }
    // Storage handlers re-render through the store; stay inside act().
    await act(async () => {
      window.dispatchEvent(new StorageEvent('storage', { key, newValue }))
    })
  }

  it('applies a mode another tab switched to', async () => {
    const { applyTheme } = await import('./prefs')
    await mountSubscriber()

    applyTheme('dark') // local toggle first: this tab never sees its own event
    expect(document.documentElement.dataset.theme).toBe('dark')

    writeAsOtherTab('hp-theme', 'light')

    expect(document.documentElement.dataset.theme).toBe('light')
    expect(localStorage.getItem('hp-theme')).toBe('light')
  })

  it('reads a removed key as reset to system (#1754 shape: absent = system)', async () => {
    const { applyTheme } = await import('./prefs')
    await mountSubscriber()

    applyTheme('dark')
    writeAsOtherTab('hp-theme', null)

    expect('theme' in document.documentElement.dataset).toBe(false)
  })

  it('maps a whole-area clear (key null) to defaults on both axes', async () => {
    const { applyTheme } = await import('./prefs')
    await mountSubscriber()

    applyTheme('dark')
    writeAsOtherTab('hp-palette', 'ocean')
    expect(document.documentElement.dataset.theme).toBe('dark')

    writeAsOtherTab(null, null)

    expect('theme' in document.documentElement.dataset).toBe(false)
    // The palette applier normalises to the named default rather than leaving
    // the attribute absent -- getThemeName()/gallery need an answerable DOM.
    expect(document.documentElement.dataset.hpTheme).toBe('claude')
  })

  it('applies a palette written elsewhere and resets it on removal', async () => {
    await mountSubscriber()

    writeAsOtherTab('hp-palette', 'sunset')
    expect(document.documentElement.dataset.hpTheme).toBe('sunset')

    writeAsOtherTab('hp-palette', null)

    expect(document.documentElement.dataset.hpTheme).toBe('claude')
  })

  it('normalises a malformed foreign value back to the boot-contract default', async () => {
    await mountSubscriber()

    // Same read the pre-paint boot script makes: not shaped like a name --
    // even though present -- reads as absent, and absent is the default.
    writeAsOtherTab('hp-palette', 'Not A Palette Name!!')

    expect(document.documentElement.dataset.hpTheme).toBe('claude')
  })

  it('never echoes through the appliers after resolving a foreign write', async () => {
    await mountSubscriber()

    writeAsOtherTab('hp-theme', 'light')
    writeAsOtherTab('hp-theme', 'light')

    // Reacting cannot rewrite storage into a state another handler would see
    // as new: same-value writes produce no event anywhere, and the guard
    // short-circuits the rest. If this ever regressed into ping-pong, the
    // extra pass above flips out via the mismatched old/new assertions.
    expect(document.documentElement.dataset.theme).toBe('light')
    expect(localStorage.getItem('hp-theme')).toBe('light')
  })

  it('arms the storage bridge from pullAppearance() alone -- no subscriber required', async () => {
    // The gap a review found: registration lived only in useAppearanceKey's
    // subscribe, and chartless pages -- settings, where themes are actually
    // changed -- render none. pullAppearance runs at root-route mount on
    // every page, so it must reach the registration before anything else
    // does. The arming is synchronous ahead of the network reconcile, so no
    // awaiting is needed here either.
    const { pullAppearance } = await import('./prefs')
    void pullAppearance()

    await writeAsOtherTab('hp-theme', 'dark')

    expect(document.documentElement.dataset.theme).toBe('dark')
  })

  it('likewise arms the OS-preference bridge from pullAppearance()', async () => {
    const bridge = { subscribed: false }
    vi.stubGlobal(
      'matchMedia',
      ((query: string) => ({
        matches: false,
        media: query,
        addEventListener: () => {
          bridge.subscribed = true
        },
        removeEventListener: () => {},
        addListener: () => {},
        removeListener: () => {},
      })) as unknown as typeof window.matchMedia,
    )
    const { pullAppearance } = await import('./prefs')
    void pullAppearance()

    // Without the arm-at-root path this stays false: the query was never
    // subscribed, and OS flips die exactly like the storage ones did, just
    // as silently.
    expect(bridge.subscribed).toBe(true)
  })
})
