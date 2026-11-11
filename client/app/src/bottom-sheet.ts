export interface BottomSheetOptions {
  title: string;
  render: (container: HTMLElement) => void;
  /** Runs once before this view is replaced or the sheet is dismissed. */
  onClose?: () => void;
}

export interface BottomSheetController {
  open: (options: BottomSheetOptions) => void;
  close: () => void;
  isOpen: () => boolean;
}

const controllers = new WeakMap<HTMLDialogElement, BottomSheetController>();

/** Native modal semantics keep the background inert and keyboard focus inside. */
export function createBottomSheet(dialog: HTMLDialogElement): BottomSheetController {
  const existing = controllers.get(dialog);
  if (existing) return existing;

  const title = dialog.querySelector<HTMLElement>('#sheet-title');
  const content = dialog.querySelector<HTMLElement>('#sheet-content');
  const closeButton = dialog.querySelector<HTMLButtonElement>('.sheet-close');
  if (!title || !content || !closeButton) {
    throw new Error('Bottom sheet requires #sheet-title, #sheet-content and .sheet-close');
  }

  title.tabIndex = -1;
  dialog.setAttribute('aria-labelledby', title.id);
  closeButton.type = 'button';
  if (!closeButton.hasAttribute('aria-label')) closeButton.setAttribute('aria-label', 'Закрыть');

  let sessionActive = false;
  let opener: HTMLElement | null = null;
  let onClose: (() => void) | undefined;
  let outsidePointer: number | null = null;

  const releaseView = () => {
    const cleanup = onClose;
    onClose = undefined;
    try {
      // Moving an existing live panel back to its owner must happen before
      // replaceChildren, so its listeners and controls remain intact.
      cleanup?.();
    } finally {
      content.replaceChildren();
      content.scrollTop = 0;
      content.classList.remove('is-scrolling');
    }
  };

  const finishClose = () => {
    if (!sessionActive) return;
    sessionActive = false;
    outsidePointer = null;
    const focusTarget = opener;
    opener = null;
    try {
      releaseView();
    } finally {
      if (focusTarget?.isConnected && !focusTarget.closest('[inert]')) {
        focusTarget.focus({ preventScroll: true });
      }
    }
  };

  const close = () => {
    try {
      if (dialog.open) dialog.close();
    } finally {
      finishClose();
    }
  };

  const outsideDialog = (event: PointerEvent) => {
    const bounds = dialog.getBoundingClientRect();
    return event.clientX < bounds.left || event.clientX > bounds.right
      || event.clientY < bounds.top || event.clientY > bounds.bottom;
  };

  dialog.addEventListener('pointerdown', (event) => {
    outsidePointer = event.isPrimary && event.button === 0
      && event.target === dialog && outsideDialog(event) ? event.pointerId : null;
  });
  dialog.addEventListener('pointerup', (event) => {
    const dismiss = outsidePointer === event.pointerId && event.button === 0
      && event.target === dialog && outsideDialog(event);
    outsidePointer = null;
    if (dismiss) {
      event.preventDefault();
      event.stopPropagation();
      close();
    }
  });
  dialog.addEventListener('pointercancel', () => { outsidePointer = null; });
  dialog.addEventListener('cancel', (event) => {
    event.preventDefault();
    close();
  });
  dialog.addEventListener('close', () => {
    // close events are queued. Ignore a previous event if open() already
    // started a new session synchronously after close().
    if (!dialog.open) finishClose();
  });
  closeButton.addEventListener('click', close);
  dialog.addEventListener('wheel', (event) => {
    if (event.target === dialog) event.preventDefault();
  }, { passive: false });

  const controller: BottomSheetController = {
    open(options) {
      if (!dialog.open) {
        const focused = dialog.ownerDocument.activeElement;
        opener = focused instanceof HTMLElement && !dialog.contains(focused) ? focused : null;
        sessionActive = true;
      }
      outsidePointer = null;
      try {
        releaseView();
        title.textContent = options.title;
        onClose = options.onClose;
        options.render(content);
        if (!dialog.open) dialog.showModal();
        title.focus({ preventScroll: true });
      } catch (error) {
        try {
          close();
        } finally {
          throw error;
        }
      }
    },
    close,
    isOpen: () => dialog.open,
  };
  controllers.set(dialog, controller);
  return controller;
}
