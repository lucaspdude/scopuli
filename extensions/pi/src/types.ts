// Shared types for the scopuli pi extension.

export interface Credentials {
  url: string;
  token: string;
}

export type ConnectionState =
  | { kind: "no-credentials" }
  | { kind: "checking"; url: string }
  | { kind: "up"; url: string; keyCount: number; scope: "all" | "read" | "manage"; relativeTime: string }
  | { kind: "expired"; url: string }
  | { kind: "revoked"; url: string }
  | { kind: "unreachable"; url: string; reason: string }
  | { kind: "auth-missing"; url: string };

export interface PiAPI {
  ui: {
    statusBar: {
      register: (id: string, render: (state: ConnectionState) => string) => void;
    };
  };
  registerCommand: (cmd: { name: string; description: string; handler: (args: unknown) => Promise<void> }) => void;
}
