// broken-manifest plugin entry — deliberately missing the Cordis contract.
// There is no `name` export and no `apply` function, so the scanner must flag
// this entry as invalid.
export const somethingElse = 42
