import { convertFromDIDDocument } from "./convertDIDDocument";

export async function convertFromDIDWeb(didUrl: string) {
  if (!didUrl.startsWith("did:web:")) {
    throw new Error("Unable to decode did:web " + didUrl);
  }

  const keycode = didUrl.substring(8).split("#")[0];
  // replace any : with a /
  const path = keycode.replaceAll(":", "/");
  const url = "https://" + path + "/.well-known/did.json";

  // fetch the document
  const response = await fetch(url).then((r) => r.json());
  return convertFromDIDDocument(response);
}
