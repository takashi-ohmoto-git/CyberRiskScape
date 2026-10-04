/** @type {import('tailwindcss').Config} */
export default {
  // コンポーネント型の color（bg-*）は YAML に書かれるため、同梱ライブラリも走査対象に含める。
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}', './data/component-library/**/*.yaml'],
  theme: {
    extend: {},
  },
  plugins: [require('tailwindcss-animate')],
};
