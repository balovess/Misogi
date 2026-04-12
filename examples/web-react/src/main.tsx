/**
 * Application entry point for Misogi React frontend.
 *
 * Mounts the root React component into the DOM and initializes
 * the application. This file is referenced by index.html as
 * the primary JavaScript module.
 *
 * @module main
 */

import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

/**
 * Get the root DOM element where React will mount.
 * Falls back to creating a new div if #root doesn't exist.
 */
const rootElement = document.getElementById('root');

if (!rootElement) {
  throw new Error(
    'Failed to find root element. Ensure index.html contains <div id="root"></div>',
  );
}

/**
 * Create React root and render the application.
 *
 * Uses React 18's createRoot API for concurrent features support.
 * Enables strict mode for development-time checks and warnings.
 */
const root = ReactDOM.createRoot(rootElement);

root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
