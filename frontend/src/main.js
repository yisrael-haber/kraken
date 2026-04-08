import './style.css';
import './app.css';

import logo from './assets/images/kraken_logo.png';
import {startApp} from './app/controller';

const root = document.querySelector('#app');

startApp(root, {logo});
