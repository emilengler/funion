# SPDX-License-Identifier: ISC

defmodule TorProto.Router do
  @enforce_keys [:identity, :ip4, :orport, :keys]
  defstruct nickname: nil,
            identity: nil,
            ip4: nil,
            ip6: nil,
            orport: nil,
            keys: nil

  @type t :: %TorProto.Router{
          nickname: String.t() | nil,
          identity: binary(),
          ip4: :inet.ip4_address(),
          ip6: :inet.ip6_address() | nil,
          orport: integer(),
          keys: TorProto.Router.Keys.t()
        }
end
