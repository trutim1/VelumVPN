/** Reveal only the scrollbar that is moving; never retain raw wheel/key data. */
export function installScrollActivity(document: Document, idleDelay = 700): () => void {
  const view = document.defaultView;
  if (!view) return () => {};
  const active = new Map<Element, number>();

  const reset = () => {
    for (const [element, timer] of active) {
      view.clearTimeout(timer);
      element.classList.remove('is-scrolling');
    }
    active.clear();
  };
  const onScroll = (event: Event) => {
    const target = event.target === document ? document.scrollingElement : event.target;
    if (!(target instanceof view.Element)) return;
    if (target.scrollHeight <= target.clientHeight && target.scrollWidth <= target.clientWidth) return;

    const previous = active.get(target);
    if (previous !== undefined) view.clearTimeout(previous);
    target.classList.add('is-scrolling');
    active.set(target, view.setTimeout(() => {
      target.classList.remove('is-scrolling');
      active.delete(target);
    }, idleDelay));
  };
  const onVisibilityChange = () => {
    if (document.hidden) reset();
  };

  // Scroll doesn't bubble. Capture also sees newly rendered screen containers,
  // including scrolling caused by keyboard navigation and touch gestures.
  document.addEventListener('scroll', onScroll, { capture: true, passive: true });
  document.addEventListener('visibilitychange', onVisibilityChange);
  view.addEventListener('pagehide', reset);
  return () => {
    document.removeEventListener('scroll', onScroll, true);
    document.removeEventListener('visibilitychange', onVisibilityChange);
    view.removeEventListener('pagehide', reset);
    reset();
  };
}
