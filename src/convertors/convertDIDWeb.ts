import { convertFromDIDDocument } from "./convertDIDDocument";

export async function convertFromDIDWeb(didUrl: string) {
  if (!didUrl.startsWith("did:web:")) {
    throw new Error("Unable to decode did:web " + didUrl);
  }

  const keycode = didUrl.substring(8).split("#")[0];
  // replace any : with a /
  const path = keycode.replaceAll(":", "/").replaceAll('%3A', ':');
  let url = "https://" + path + "/.well-known/did.json";
  if (path.indexOf('/') >= 0) {
    // if the url contains a subpath, do not append .well-known
    // url cannot end with a slash (colon), so any slash means there is a subpath
    // (but a slash at index 0 means there is no domain...)
    url = "https://" + path + "/did.json";
  }

  // fetch the document
  const response = await fetch(url).then((r) => r.json());
  return await convertFromDIDDocument(response);
}
