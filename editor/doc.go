// Package editor is the M3 layer of the user-content platform.
// It contains the dashboard-side helpers used by the first
// consumer: HTML/CSS paste and upload, sanitizer Report
// rendering in the UI, and the contract for the sandboxed
// preview iframe (M3 §4: <iframe sandbox="" src=...> pointed
// at the isolated user-content origin, never
// dangerouslySetInnerHTML on the app origin).
//
// The package never sees raw content. Everything it accepts
// has already been routed through usercontent.Sanitizer. Its
// job is to surface what the sanitizer removed so authors
// understand why their content changed, and to keep the
// preview isolated from the dashboard origin.
package editor
