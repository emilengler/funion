# SPDX-License-Identifier: ISC

defmodule TorDir.Router do
  defstruct nickname: nil,
            identity: nil,
            ip4: nil,
            ip6: nil,
            orport: nil,
            keys: nil
end
