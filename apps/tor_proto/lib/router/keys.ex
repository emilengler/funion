# SPDX-License-Identifier: ISC

defmodule TorProto.Router.Keys do
  defstruct rsa_identity: nil,
            rsa_onion: nil,
            rsa_connection: nil,
            x25519_ntor: nil,
            ed25519_identity: nil,
            ed25519_signing: nil,
            ed25519_authentication: nil
end
