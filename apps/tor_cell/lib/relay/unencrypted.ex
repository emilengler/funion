defmodule TorCell.Relay.Unencrypted do
  defstruct cmd: nil,
            stream_id: nil,
            payload: nil,
            padding: nil
end
