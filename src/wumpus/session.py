# -*- coding: utf-8 -*-
"""
TRACE_THE_WUMPUS
Copyright (C) 2014-2024 Leitwert GmbH

This software is distributed under the terms of the MIT license.
It can be found in the LICENSE file or at https://opensource.org/licenses/MIT.

Author Johann SCHLAMP <schlamp@leitwert.net>
Author Leonhard RABEL <rabel@leitwert.net>
"""

# System imports
import datetime
import random

# Local imports
from wumpus.const import ROOMS
from wumpus.const import TIMEOUT
from wumpus.const import Output


class Session:
    """ Keep track of player's game session.
    """
    def __init__(self, debug=False):
        """ Initialize game session.
        """
        # Prepare internals
        self.initial_entities = None
        self.entities = None
        self.last_update = self.utc()
        self.last_help = -1
        self.live = False
        self.lost = False
        self.won = False
        self.ammo = 5
        self.debug = debug

    ##############
    # MANAGEMENT #
    ##############

    def new(self, entities=None):
        """ Create new session with new entities.
        """
        # Reset internals
        self.live = True
        self.lost = False
        self.won = False
        self.ammo = 5

        # Place entities
        if entities is None:
            entities = random.sample(range(1, len(ROOMS) + 1), 6)
            self.initial_entities = entities

        class Entities:
            """ Keep track of entity locations.
            """
            def __init__(self, player, wumpus, pit1, pit2, bat1, bat2):
                """ Initialize entity locations.
                """
                # Prepare internals
                self.player = player
                self.wumpus = wumpus
                self.pit1 = pit1
                self.pit2 = pit2
                self.bat1 = bat1
                self.bat2 = bat2

        # Create entities
        self.entities = Entities(*entities)

    def reset(self):
        """ Create new session with previous entities.
        """
        # Invoke session creation
        return self.new(entities=self.initial_entities)

    def clear(self):
        """ Clear session.
        """
        # Reset internals
        self.initial_entities = None
        self.entities = None
        self.live = False

    def update(self):
        """ Update session.
        """
        # Update access time
        self.last_update = self.utc()

    def expired(self):
        """ Check if session has expired.
        """
        # Check expiry and set/return timeout flag
        expired = self.utc() - self.last_update >= TIMEOUT
        if expired is True:
            self.live = False
        return expired

    ##########
    # OUTPUT #
    ##########

    @staticmethod
    def output_ipv4():
        """ Output ipv4 screen.
        """
        # Return static ipv4 output
        return Output.INFO_IPV4[:-1]

    @staticmethod
    def output_expired():
        """ Output expired session screen.
        """
        # Return static expiry output
        return [
            Output.GAME_EMPTY,
            Output.ACTION_EXPIRED,
            Output.GAME_EMPTY,
            Output.GAME_PLAY,
        ]

    @staticmethod
    def output_invalid():
        """ Output invalid command screen.
        """
        # Return static error output
        return [Output.GAME_EMPTY, Output.ACTION_UNKNOWN]

    @staticmethod
    def output_title():
        """ Output title screen.
        """
        # Return static title output
        return Output.INFO_TITLE

    @staticmethod
    def output_win():
        """ Output win screen.
        """
        # Return static win output
        return [
            Output.GAME_EMPTY,
            Output.GAME_WIN,
            Output.GAME_EMPTY,
            Output.GAME_PLAY,
            Output.GAME_REPLAY,
        ]

    @staticmethod
    def output_loss():
        """ Output loss screen.
        """
        # Return static loss output
        return [
            Output.GAME_EMPTY,
            Output.GAME_LOSS,
            Output.GAME_EMPTY,
            Output.GAME_PLAY,
            Output.GAME_REPLAY,
        ]

    @staticmethod
    def output_map():
        """ Output map screen.
        """
        # Return static map output
        return Output.INFO_MAP

    def output_help(self):
        """ Output help screen.
        """
        # Update last help index
        self.last_help = (self.last_help + 1) % 4

        # Return current help output
        return [
            Output.INFO_HELP1,
            Output.INFO_HELP2,
            Output.INFO_HELP3,
            Output.INFO_HELP4
        ][self.last_help]

    def output_state(self, initial=False):
        """ Output current state (optionally including initial text).
        """
        # Output debug messages
        win_loss = 'win, ' if self.won is True else ('loss, ' if self.lost is True else '')
        self.log_debug(f'STATE [{win_loss}player={self.entities.player}, wumpus={self.entities.wumpus}, '
                       f'pits=({",".join(str(r) for r in sorted(set([self.entities.pit1, self.entities.pit2])))}), '
                       f'bats=({",".join(str(r) for r in sorted(set([self.entities.bat1, self.entities.bat2])))}), '
                       f'arrows={self.ammo}]')

        # Player already won
        if self.won is True:
            return self.output_win()

        # Player already lost
        if self.lost is True:
            return self.output_loss()

        # Prepare state output
        output = [Output.GAME_EMPTY]

        # Title
        if initial is True:
            output.append(Output.GAME_HUNT)
            output.append(Output.GAME_EMPTY)

        # Handle hazards
        has_hazard = False
        for locations, warning in (
            ((self.entities.wumpus, ), Output.HAZARD_WUMPUS),
            ((self.entities.pit1, self.entities.pit2), Output.HAZARD_PIT),
            ((self.entities.bat1, self.entities.bat2), Output.HAZARD_BAT),
        ):
            for location in locations:
                if self.entities.player in ROOMS[location]:
                    output.append(warning)
                    has_hazard = True
        if has_hazard is True:
            output.append(Output.GAME_EMPTY)

        # Handle current location
        output.append(Output.STATE_POSITION[self.entities.player - 1])
        output.append(Output.STATE_TUNNELS[self.entities.player - 1])
        output.append(Output.GAME_EMPTY)

        # Ask for next action
        output.append(Output.GAME_MOVE)
        output.append(Output.GAME_SHOOT)

        # Return state output
        return output

    ###########
    # ACTIONS #
    ###########

    def move(self, room):
        """ Move to given room.
        """
        # Prepare move output
        output = list()

        # Handle invalid room
        if room not in ROOMS[self.entities.player]:
            output.append(Output.GAME_EMPTY)
            output.append(Output.ACTION_MOVE_INVALID)
            return output

        # Update player location
        self.entities.player = room

        # Interact with hazards
        output += self.hazards()
        if self.lost:
            return output

        # Move wumpus
        if self.entities.wumpus == self.entities.player:
            output.append(Output.GAME_EMPTY)
            output.append(Output.ACTION_MOVE_WUMPUS)
            output += self.wumpus()

        # Return move output
        return output

    def shoot(self, shots):
        """ Shoot to given room(s).
        """
        # Prepare shoot output
        output = [Output.GAME_EMPTY]

        # Handle invalid shots
        if len(shots) < 1 or len(shots) > 5 or len(shots) != len(set(shots)):
            # NOTE: This differs from original game (no or too many shots produced no error message)
            output.append(Output.ACTION_SHOOT_INVALID)
            return output

        # Move arrow sequentially
        current_pos = self.entities.player
        for room in shots:
            old_pos = current_pos

            # Move arrow to selected room if valid or random neighboring room otherwise
            current_pos = room if room in ROOMS[current_pos] else random.choice(ROOMS[current_pos])

            # Output debug messages
            self.log_debug(f'SHOT  [room={room}, valid=({",".join(str(r) for r in ROOMS[old_pos])}), shot={current_pos}, '
                           f'wumpus={self.entities.wumpus}]')

            # Arrow hit wumpus
            if current_pos == self.entities.wumpus:
                output.append(Output.ACTION_SHOOT_HIT)
                self.won = True
                return output

            # Arrow hit self
            if current_pos == self.entities.player:
                output.append(Output.ACTION_SHOOT_SELF)
                self.lost = True
                return output

        # No arrow hit
        output.append(Output.ACTION_SHOOT_MISSED)

        # Update/check ammo
        self.ammo -= 1
        if self.ammo == 0:
            self.lost = True
            return output

        # Move wumpus
        return output + self.wumpus()

    def hazards(self):
        """ Interact with hazards.
        """
        # Handle pits
        if self.entities.player in {self.entities.pit1, self.entities.pit2}:
            self.lost = True
            return [Output.GAME_EMPTY, Output.ACTION_MOVE_PIT]

        # Handle bats
        if self.entities.player in {self.entities.bat1, self.entities.bat2}:
            player = random.choice(list(set(range(1, len(ROOMS) + 1)) - {self.entities.bat1, self.entities.bat2}))
            self.entities.player = player
            return [Output.GAME_EMPTY, Output.ACTION_MOVE_BAT] + self.hazards()

        # No interaction
        return list()

    def wumpus(self):
        """ Move wumpus.
        """
        # Move wumpus with probability 0.25
        move = random.choice(range(4))
        if move < 3:
            self.entities.wumpus = ROOMS[self.entities.wumpus][move]

        # Wumpus wins
        if self.entities.wumpus == self.entities.player:
            self.lost = True
            return [Output.GAME_EMPTY, Output.ACTION_WUMPUS_GOTCHA]

        # Wumpus moved silently
        return list()

    ###########
    # HELPERS #
    ###########

    def log_debug(self, *args, **kwargs):
        """ Log debug message.
        """
        # Print colored console output
        if self.debug:
            print('\033[1;90m', end='')
            print(*args, **kwargs, end='')
            print('\033[0m\033[27m')

    @staticmethod
    def utc():
        """ Return current timestamp relative to UTC epoch.
        """
        return int((datetime.datetime.utcnow() - datetime.datetime(1970, 1, 1)).total_seconds())
