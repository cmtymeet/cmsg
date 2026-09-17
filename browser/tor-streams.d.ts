import type { TorStorage } from 'tor-js/wasm-file';

export interface OnionFramedStream {
  readonly closed: boolean;
  send(wire: Uint8Array): Promise<void>;
  receive(): Promise<Uint8Array>;
  close(): void;
}
export interface BrowserOnionListener {
  readonly host: string;
  readonly port: number;
  accept(): Promise<OnionFramedStream>;
  close(): void;
}
export interface BrowserOnionNode {
  connect(host: string, port: number): Promise<OnionFramedStream>;
  /** Publication deadline: integer 1..600000 ms. Strict Arti Running is required;
   * accept/read/write retain the independently configured operation deadline. */
  listen(options: { port: number; maximumStreams: number; deadlineMs: number }): Promise<BrowserOnionListener>;
  close(): void;
}
/** Requires the pinned custom TorJS service build, not the stock npm package. */
export function createTorJsOnionNode(options: {
  gateway: string | string[];
  storage?: TorStorage;
  bootstrapDeadlineMs: number;
  /** Stream operations only: integer 1..60000 ms. */
  operationDeadlineMs: number;
}): Promise<BrowserOnionNode>;
