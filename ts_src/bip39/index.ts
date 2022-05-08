import * as bip39 from 'bip39';
import { russian } from './languages/russian'

const langs: Record<string, string> = {
    'en' : 'english',
    'fr' : 'french',
    'it' : 'italian',
    'es' : 'spanish',
    'kr' : 'korean',
    'zh' : 'chinese_traditional',
    'ru' : 'russian'
}

const bip39Fork = bip39
function generateMnemonic (): string{
    let local = window.localStorage.getItem('loc')
    if( !local || !Object.keys(langs).includes(local) ) local = 'en'; 

    const bip39Lang = bip39.wordlists[langs[local]];

    const currentLanguage = local === 'ru' ? russian : bip39Lang;

    return bip39.generateMnemonic(undefined, undefined, currentLanguage)
}

bip39Fork.generateMnemonic = generateMnemonic
export default bip39Fork