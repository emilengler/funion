defmodule TorCell.Relay.Unencrypted do
  defstruct cmd: nil,
            stream_id: nil,
            payload: nil

  defp is_decrypted?(data, digest) do
    <<_, data::binary>> = data
    <<recognized::16, data::binary>> = data
    <<_::16, data::binary>> = data
    <<dig::32, _::binary>> = data

    recognized == 0 && <<digest::binary-size(4)>> == dig
  end

  @doc """
  Decrypts a RELAY TorCell by removing length(keys) onion layers from it.

  Returns a TorCell.Relay.Unencrypted if all onion layers have been removed or
  a TorCell.Relay with as much onion layers removed as possible.

  Returns a tuple containing a {true, %TorCell.Relay.Unencrypted} if all onion
  skins could have been removed successfully or a {false, %TorCell.Relay} if
  it could not be fully decrypted.

  TODO: Consider doing the digest calculation here
  """
  def decrypt(cell, keys, digest) do
    data = TorCrypto.OnionSkin.decrypt(cell.onion_skin, keys)

    if is_decrypted?(data, digest) do
      <<cmd, data::binary>> = data
      <<_::16, data::binary>> = data
      <<stream_id::16, data::binary>> = data
      <<_::32, data::binary>> = data
      <<length::16, data::binary>> = data
      <<payload::binary-size(length), data::binary>> = data

      padding_len = 509 - 11 - length
      <<_::binary-size(padding_len), _::binary>> = data

      {
        true,
        %TorCell.Relay.Unencrypted{
          cmd: cmd,
          stream_id: stream_id,
          payload: payload
        }
      }
    else
      {
        false,
        TorCell.Relay.encode(data)
      }
    end
  end
end
