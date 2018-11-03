﻿using System;
using System.Collections.Generic;
using Rubeus.Commands;

namespace Rubeus.Domain
{
    public class CommandCollection
    {
        private readonly Dictionary<string, Func<ICommand>> _availableCommands = new Dictionary<string, Func<ICommand>>();

        // How To Add A New Command:
        //  1. Create your command class in the Commands Folder
        //  2. That class must have a CommandName static property that has the Command's name
        //      and must also Implement the ICommand interface
        //  3. Put the code that does the work into the Execute() method
        //  4. Add an entry to the _availableCommands dictionary in the Constructor below.

        public CommandCollection()
        {
            _availableCommands.Add(Asktgs.CommandName, () => new Asktgs());
            _availableCommands.Add(Asktgt.CommandName, () => new Asktgt());
            _availableCommands.Add(Asreproast.CommandName, () => new Asreproast());
            _availableCommands.Add(Changepw.CommandName, () => new Changepw());
            _availableCommands.Add(Createnetonly.CommandName, () => new Createnetonly());
            _availableCommands.Add(Describe.CommandName, () => new Describe());
            _availableCommands.Add(Dump.CommandName, () => new Dump());
            _availableCommands.Add(HarvestCommand.CommandName, () => new HarvestCommand());
            _availableCommands.Add(Kerberoast.CommandName, () => new Kerberoast());
            _availableCommands.Add(Monitor.CommandName, () => new Monitor());
            _availableCommands.Add(Ptt.CommandName, () => new Ptt());
            _availableCommands.Add(Purge.CommandName, () => new Purge());
            _availableCommands.Add(RenewCommand.CommandName, () => new RenewCommand());
            _availableCommands.Add(S4u.CommandName, () => new S4u());
            _availableCommands.Add(Tgtdeleg.CommandName, () => new Tgtdeleg());
        }

        internal bool ExecuteCommand(string commandName, Dictionary<string, string> arguments)
        {
            if (string.IsNullOrEmpty(commandName)) {
                return false;
            }
            Func<ICommand> commandBuilder;
            if (!_availableCommands.TryGetValue(commandName, out commandBuilder)) {
                return false;
            }
            // Create the command object 
            ICommand command = commandBuilder.Invoke();
            // and execute it with the arguments from the command line
            command.Execute(arguments);
            return true;
        }
    }
}