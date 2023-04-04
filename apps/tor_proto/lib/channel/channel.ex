defstruct TorProto.Channel do
  @moduledoc """
  Implements the Channel (connection) of the Tor protocol.
  """
  defstruct socket: nil,
            version: nil
end
