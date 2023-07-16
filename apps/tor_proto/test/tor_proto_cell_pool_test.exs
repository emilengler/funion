# SPDX-License-Identifier: ISC

defmodule TorProtoCellPoolTest do
  use ExUnit.Case
  doctest TorProto.CellPool

  test "initializes a TorProto.CellPool" do
    assert TorProto.CellPool.init() == %TorProto.CellPool{cells: %{}, n: 0}
  end

  test "pushes to a TorProto.CellPool" do
    pool = TorProto.CellPool.init()

    pid1 = spawn(fn -> nil end)
    pid2 = spawn(fn -> nil end)
    assert pid1 != pid2

    # Push to pid1
    {pool, id} = TorProto.CellPool.push(pool, pid1, %TorCell{circ_id: 1, cmd: nil, payload: nil})

    assert pool == %TorProto.CellPool{
             cells: %{pid1 => %{0 => %TorCell{circ_id: 1, cmd: nil, payload: nil}}},
             n: 1
           }

    assert id == 0

    # Push to pid2
    {pool, id} = TorProto.CellPool.push(pool, pid2, %TorCell{circ_id: 2, cmd: nil, payload: nil})

    assert pool == %TorProto.CellPool{
             cells: %{
               pid1 => %{0 => %TorCell{circ_id: 1, cmd: nil, payload: nil}},
               pid2 => %{1 => %TorCell{circ_id: 2, cmd: nil, payload: nil}}
             },
             n: 2
           }

    assert id == 1

    # Push to pid1 again
    {pool, id} = TorProto.CellPool.push(pool, pid1, %TorCell{circ_id: 3, cmd: nil, payload: nil})

    assert pool == %TorProto.CellPool{
             cells: %{
               pid1 => %{
                 0 => %TorCell{circ_id: 1, cmd: nil, payload: nil},
                 2 => %TorCell{circ_id: 3, cmd: nil, payload: nil}
               },
               pid2 => %{1 => %TorCell{circ_id: 2, cmd: nil, payload: nil}}
             },
             n: 3
           }

    assert id == 2
  end

  test "pop from a TorProto.CellPool" do
    pid1 = spawn(fn -> nil end)
    pid2 = spawn(fn -> nil end)

    pool = %TorProto.CellPool{
      cells: %{
        pid1 => %{
          0 => %TorCell{circ_id: 1, cmd: nil, payload: nil},
          2 => %TorCell{circ_id: 3, cmd: nil, payload: nil}
        },
        pid2 => %{1 => %TorCell{circ_id: 2, cmd: nil, payload: nil}}
      },
      n: 3
    }

    # Make pid2 empty
    {pool, cell} = TorProto.CellPool.pop(pool, pid2)

    assert pool == %TorProto.CellPool{
             cells: %{
               pid1 => %{
                 0 => %TorCell{circ_id: 1, cmd: nil, payload: nil},
                 2 => %TorCell{circ_id: 3, cmd: nil, payload: nil}
               }
             },
             n: 3
           }

    assert cell == %TorCell{circ_id: 2, cmd: nil, payload: nil}

    # Try to pop from an empty pid
    {tmp, cell} = TorProto.CellPool.pop(pool, pid2)
    assert pool == tmp
    assert cell == nil

    # Remove the circ_id 3 cell from pid1
    {pool, cell} = TorProto.CellPool.pop(pool, pid1)

    assert pool == %TorProto.CellPool{
             cells: %{pid1 => %{0 => %TorCell{circ_id: 1, cmd: nil, payload: nil}}},
             n: 3
           }

    assert cell == %TorCell{circ_id: 3, cmd: nil, payload: nil}

    # Now be totally empty
    {pool, cell} = TorProto.CellPool.pop(pool, pid1)
    assert pool == %TorProto.CellPool{cells: %{}, n: 3}
    assert cell == %TorCell{circ_id: 1, cmd: nil, payload: nil}

    # And get a nil
    {tmp, cell} = TorProto.CellPool.pop(pool, pid1)
    assert pool == tmp
    assert cell == nil
  end

  test "takes from a TorProto.CellPool" do
    pid1 = spawn(fn -> nil end)
    pid2 = spawn(fn -> nil end)

    pool = %TorProto.CellPool{
      cells: %{
        pid1 => %{
          0 => %TorCell{circ_id: 1, cmd: nil, payload: nil},
          2 => %TorCell{circ_id: 3, cmd: nil, payload: nil}
        },
        pid2 => %{1 => %TorCell{circ_id: 2, cmd: nil, payload: nil}}
      },
      n: 3
    }

    # Make pid2 empty
    {pool, cell} = TorProto.CellPool.take(pool, pid2, 1)

    assert pool == %TorProto.CellPool{
             cells: %{
               pid1 => %{
                 0 => %TorCell{circ_id: 1, cmd: nil, payload: nil},
                 2 => %TorCell{circ_id: 3, cmd: nil, payload: nil}
               }
             },
             n: 3
           }

    assert cell == %TorCell{circ_id: 2, cmd: nil, payload: nil}

    # Try to take from an empty pid
    {tmp, cell} = TorProto.CellPool.take(pool, pid2, 1)
    assert pool == tmp
    assert cell == nil

    # Remove the circ_id 3 cell from pid1
    {pool, cell} = TorProto.CellPool.take(pool, pid1, 2)

    assert pool == %TorProto.CellPool{
             cells: %{pid1 => %{0 => %TorCell{circ_id: 1, cmd: nil, payload: nil}}},
             n: 3
           }

    assert cell == %TorCell{circ_id: 3, cmd: nil, payload: nil}

    # Now be totally empty
    {pool, cell} = TorProto.CellPool.take(pool, pid1, 0)
    assert pool == %TorProto.CellPool{cells: %{}, n: 3}
    assert cell == %TorCell{circ_id: 1, cmd: nil, payload: nil}

    # And get a nil
    {tmp, cell} = TorProto.CellPool.take(pool, pid1, 0)
    assert pool == tmp
    assert cell == nil
  end
end
