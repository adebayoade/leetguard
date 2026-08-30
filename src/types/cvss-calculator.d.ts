declare module 'cvss-calculator' {
  export default class Cvss {
    constructor(vector: string);
    getBaseScore(): number | null | undefined | NaN;
  }
}
