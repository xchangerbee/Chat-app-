import type { Metadata, Viewport } from 'next';
import './globals.css';
export const metadata: Metadata = { title: 'Chat — private team messaging', description: "A calm, private space for your team's one-to-one conversations.", applicationName: 'Chat', robots: { index: false, follow: false } };
export const viewport: Viewport = { width: 'device-width', initialScale: 1, themeColor: '#f7f8fc' };
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) { return <html lang='en'><body>{children}</body></html>; }
