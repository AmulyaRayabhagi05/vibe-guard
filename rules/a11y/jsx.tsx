// Test fixture for rules/a11y/jsx.yaml (ruleid lines must match, ok lines must not).
import { TrashIcon } from "@heroicons/react/24/outline";

export function Gallery({ photos, onPick, play }) {
  return (
    <section>
      {/* ruleid: vc-a11y-img-alt */}
      <img src="/hero.png" className="w-full" />
      {/* ok: vc-a11y-img-alt */}
      <img src="/logo.png" alt="Acme logo" />
      {/* ok: vc-a11y-img-alt */}
      <img src="/divider.png" alt="" />

      {/* ruleid: vc-a11y-click-without-keyboard */}
      <div className="card" onClick={() => onPick(1)}>Pick me</div>
      {/* ok: vc-a11y-click-without-keyboard */}
      <button onClick={() => onPick(2)}>Pick me</button>
      {/* ok: vc-a11y-click-without-keyboard */}
      <div role="button" tabIndex={0} onClick={() => onPick(3)} onKeyDown={(e) => e.key === "Enter" && onPick(3)}>Pick</div>

      {/* ruleid: vc-a11y-input-label */}
      <input type="email" placeholder="Email" />
      {/* ok: vc-a11y-input-label */}
      <input type="email" id="email" />
      {/* ok: vc-a11y-input-label */}
      <input type="search" aria-label="Search photos" />
      {/* ok: vc-a11y-input-label */}
      <input type="hidden" name="csrf" />
      <label>
        Name
        {/* ok: vc-a11y-input-label */}
        <input type="text" />
      </label>

      {/* ruleid: vc-a11y-positive-tabindex */}
      <span tabIndex={3}>Skip</span>
      {/* ok: vc-a11y-positive-tabindex */}
      <span tabIndex={0}>Ok</span>

      {/* ruleid: vc-a11y-anchor-no-href */}
      <a onClick={() => play()}>Play</a>
      {/* ok: vc-a11y-anchor-no-href */}
      <a href="/play" onClick={() => play()}>Play</a>

      {/* ruleid: vc-a11y-icon-button-name */}
      <button onClick={() => onPick(0)}><TrashIcon className="h-4" /></button>
      {/* ok: vc-a11y-icon-button-name */}
      <button aria-label="Delete photo" onClick={() => onPick(0)}><TrashIcon className="h-4" /></button>

      {/* ruleid: vc-a11y-autoplay-media */}
      <video src="/promo.mp4" autoPlay></video>
      {/* ok: vc-a11y-autoplay-media */}
      <video src="/loop.mp4" autoPlay muted loop></video>

      {/* ruleid: vc-a11y-iframe-title */}
      <iframe src="https://maps.example.com/embed"></iframe>
      {/* ok: vc-a11y-iframe-title */}
      <iframe src="https://maps.example.com/embed" title="Map of our office"></iframe>

      {/* ruleid: vc-a11y-focus-outline-removed */}
      <input id="q" className="border outline-none" />
      {/* ok: vc-a11y-focus-outline-removed */}
      <input id="q2" className="border outline-none focus-visible:ring-2" />
    </section>
  );
}

export function RootLayout({ children }) {
  // ruleid: vc-a11y-html-lang
  return (
    <html>
      <body>{children}</body>
    </html>
  );
}
