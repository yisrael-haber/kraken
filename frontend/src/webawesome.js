import '@awesome.me/webawesome/dist/styles/themes/default.css';
import '@awesome.me/webawesome/dist/styles/color/variants.css';
import '@awesome.me/webawesome/dist/styles/utilities/align-items.css';
import '@awesome.me/webawesome/dist/styles/utilities/flex-wrap.css';
import '@awesome.me/webawesome/dist/styles/utilities/gap.css';
import '@awesome.me/webawesome/dist/styles/utilities/justify-content.css';
import '@awesome.me/webawesome/dist/styles/utilities/layout.css';
import '@awesome.me/webawesome/dist/styles/utilities/variants.css';
import {registerIconLibrary} from '@awesome.me/webawesome/dist/components/icon/library.js';
import barsIcon from '@fortawesome/fontawesome-free/svgs/solid/bars.svg';
import copyIcon from '@fortawesome/fontawesome-free/svgs/regular/copy.svg';
import diagramProjectIcon from '@fortawesome/fontawesome-free/svgs/solid/diagram-project.svg';
import fileCodeIcon from '@fortawesome/fontawesome-free/svgs/solid/file-code.svg';
import fingerprintIcon from '@fortawesome/fontawesome-free/svgs/solid/fingerprint.svg';
import pauseIcon from '@fortawesome/fontawesome-free/svgs/solid/pause.svg';
import pencilIcon from '@fortawesome/fontawesome-free/svgs/solid/pencil.svg';
import playIcon from '@fortawesome/fontawesome-free/svgs/solid/play.svg';
import screwdriverWrenchIcon from '@fortawesome/fontawesome-free/svgs/solid/screwdriver-wrench.svg';
import stopIcon from '@fortawesome/fontawesome-free/svgs/solid/stop.svg';
import xmarkIcon from '@fortawesome/fontawesome-free/svgs/solid/xmark.svg';
import '@awesome.me/webawesome/dist/components/badge/badge.js';
import '@awesome.me/webawesome/dist/components/avatar/avatar.js';
import '@awesome.me/webawesome/dist/components/button/button.js';
import '@awesome.me/webawesome/dist/components/checkbox/checkbox.js';
import '@awesome.me/webawesome/dist/components/checkbox-group/checkbox-group.js';
import '@awesome.me/webawesome/dist/components/callout/callout.js';
import '@awesome.me/webawesome/dist/components/copy-button/copy-button.js';
import '@awesome.me/webawesome/dist/components/input/input.js';
import '@awesome.me/webawesome/dist/components/icon/icon.js';
import '@awesome.me/webawesome/dist/components/number-input/number-input.js';
import '@awesome.me/webawesome/dist/components/option/option.js';
import '@awesome.me/webawesome/dist/components/page/page.js';
import '@awesome.me/webawesome/dist/components/select/select.js';
import '@awesome.me/webawesome/dist/components/tab-group/tab-group.js';

const krakenIcons = {
    bars: barsIcon,
    copy: copyIcon,
    'diagram-project': diagramProjectIcon,
    'file-code': fileCodeIcon,
    fingerprint: fingerprintIcon,
    pause: pauseIcon,
    pencil: pencilIcon,
    play: playIcon,
    'screwdriver-wrench': screwdriverWrenchIcon,
    stop: stopIcon,
    xmark: xmarkIcon,
};

registerIconLibrary('kraken', {
    resolver: (name) => krakenIcons[name] || '',
});
import '@awesome.me/webawesome/dist/components/tree/tree.js';
