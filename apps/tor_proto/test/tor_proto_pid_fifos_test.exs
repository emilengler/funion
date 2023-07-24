# SPDX-License-Identifier: ISC

defmodule TorProtoPidFifosTest do
  use ExUnit.Case
  doctest TorProto.PidFifos

  test "initializes a TorProto.PidFifos" do
    assert TorProto.PidFifos.init() == %{}
  end

  test "enqueues a TorProto.PidFifos" do
    pid1 = spawn(fn -> nil end)
    pid2 = spawn(fn -> nil end)

    fifos = TorProto.PidFifos.init()
    fifos = TorProto.PidFifos.enqueue(fifos, pid1, 1)
    assert fifos == %{pid1 => {[1], []}}
    fifos = TorProto.PidFifos.enqueue(fifos, pid2, 1)
    assert fifos == %{pid1 => {[1], []}, pid2 => {[1], []}}
    fifos = TorProto.PidFifos.enqueue(fifos, pid1, 2)
    assert fifos == %{pid1 => {[2], [1]}, pid2 => {[1], []}}
  end

  test "deques a TorProto.PidFifos" do
    pid1 = spawn(fn -> nil end)
    pid2 = spawn(fn -> nil end)
    fifos = %{pid1 => {[2], [1]}, pid2 => {[1], []}}

    {fifos, cell} = TorProto.PidFifos.dequeue(fifos, pid2)
    assert fifos == %{pid1 => {[2], [1]}}
    assert cell == 1

    {fifos, cell} = TorProto.PidFifos.dequeue(fifos, pid2)
    assert fifos == %{pid1 => {[2], [1]}}
    assert cell == nil

    {fifos, cell} = TorProto.PidFifos.dequeue(fifos, pid1)
    assert fifos == %{pid1 => {[], [2]}}
    assert cell == 1

    {fifos, cell} = TorProto.PidFifos.dequeue(fifos, pid1)
    assert fifos == %{}
    assert cell == 2

    {fifos, cell} = TorProto.PidFifos.dequeue(fifos, pid1)
    assert fifos == %{}
    assert cell == nil
  end

  test "kills a TorProto.PidFifo" do
    pid1 = spawn(fn -> nil end)
    fifos = %{pid1 => {[2], [1]}}

    fifos = TorProto.PidFifos.kill(fifos, pid1)
    assert fifos == %{}
  end
end
