import type {
  LicenseConfig,
  NavBarConfig,
  ProfileConfig,
  SiteConfig,
} from './types/config'
import { LinkPreset } from './types/config'

export const siteConfig: SiteConfig = {
  title: 'Enzo Cadoni',
  subtitle: 'Site Perso',
  lang: 'en',         // 'en', 'zh_CN', 'zh_TW', 'ja'
  themeColor: {
    hue: 25,         // Default hue for the theme color, from 0 to 360. e.g. red: 0, teal: 200, cyan: 250, pink: 345
    fixed: false,     // Hide the theme color picker for visitors
  },
  banner: {
    enable: false,
    src: 'assets',   // Relative to the /src directory. Relative to the /public directory if it starts with '/'
    position: 'center', // Equivalent to object-position, defaults center
  },
  favicon: [    
    // {
    //   src: '/favicon/icon.png',    // Path of the favicon, relative to the /public directory
    //   theme: 'light',              // (Optional) Either 'light' or 'dark', set only if you have different favicons for light and dark mode
    //   sizes: '32x32',              // (Optional) Size of the favicon, set only if you have favicons of different sizes
    // }
  ]
}

export const navBarConfig: NavBarConfig = {
  links: [
    LinkPreset.Home,
    LinkPreset.Archive,
    // LinkPreset.About,
    {
      name: 'Root-Me',
      url: 'https://www.root-me.org/3C4D',
      external: true,
    },
    {
      name: 'NewbieContest',
      url: 'https://www.newbiecontest.org/index.php?page=info_membre&id=88218',
      external: true,
    },
    {
      name: 'HackTheBox',
      url: 'https://app.hackthebox.com/users/523147',
      external: true,
    },
  ],
}

export const profileConfig: ProfileConfig = {
  avatar: 'assets/images/3c4d.jpg',  // Relative to the /src directory. Relative to the /public directory if it starts with '/'
  name: 'Enzo Cadoni',
  bio: 'Cybersecurity - Pentest - CTF',
  links: [
    {
      name: 'Root-Me',
      icon: 'simple-icons:rootme',
      url: 'https://www.root-me.org/3C4D',
    },
    {
      name: 'Github',
      icon: 'fa6-brands:github',
      url: 'https://github.com/3C4D',
    },
    {
      name: 'LinkedIn',
      icon: 'fa6-brands:linkedin',
      url: 'https://www.linkedin.com/in/enzo-cadoni',
    },
  ],
}

export const licenseConfig: LicenseConfig = {
  enable: false,
  name: 'CC BY-NC-SA 4.0',
  url: 'https://creativecommons.org/licenses/by-nc-sa/4.0/',
}
