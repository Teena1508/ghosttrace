import React from 'react';
import type { ErrorInfo, ReactNode } from 'react';

interface WorkspaceErrorBoundaryProps {
  children: ReactNode;
  /** Human-readable name of the guarded area, shown in the fallback */
  label: string;
  /** Render the fallback as a fixed toast (for overlays such as modals and drawers) */
  floating?: boolean;
  onReset?: () => void;
}

interface WorkspaceErrorBoundaryState {
  error: Error | null;
}

/**
 * Contains a rendering crash to one view so the rest of the dashboard stays usable,
 * instead of React unmounting the whole app and leaving a blank screen.
 */
export class WorkspaceErrorBoundary extends React.Component<WorkspaceErrorBoundaryProps, WorkspaceErrorBoundaryState> {
  state: WorkspaceErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): WorkspaceErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error(`[GhostTrace] ${this.props.label} failed to render:`, error, info.componentStack);
  }

  private handleReset = () => {
    this.setState({ error: null });
    this.props.onReset?.();
  };

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;

    return (
      <div
        className="error-banner"
        role="alert"
        style={this.props.floating ? { position: 'fixed', bottom: 24, right: 24, maxWidth: 480, zIndex: 2000 } : undefined}
      >
        <h3>{this.props.label} could not be displayed</h3>
        <p>{error.message}</p>
        <button className="btn-refresh" onClick={this.handleReset}>
          {this.props.floating ? 'Dismiss' : '↻ Try again'}
        </button>
      </div>
    );
  }
}
