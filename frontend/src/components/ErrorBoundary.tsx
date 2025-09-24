import { Component, ReactNode } from "react";

type Props = { children: ReactNode };
type State = { hasError: boolean; msg?: string };

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false };

  static getDerivedStateFromError(err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { hasError: true, msg };
  }

  componentDidCatch(error: any, info: any) {
    console.error("💥 ErrorBoundary caught:", error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: 24, fontFamily: "system-ui" }}>
          <h2>Something went wrong.</h2>
          <p style={{ color: "#a00" }}>{this.state.msg}</p>
          <button onClick={() => location.reload()}>Reload</button>
        </div>
      );
    }
    return this.props.children;
  }
}
