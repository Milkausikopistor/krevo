// First module of the web app: installs Buffer before any other project module runs.
import { installBuffer } from './shims/buffer.js';
installBuffer();
