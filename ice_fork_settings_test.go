// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"reflect"
	"testing"

	"github.com/pion/ice/v4"
	"github.com/stretchr/testify/require"
)

func TestICECandidatePairPacketHandlerForwarding(t *testing.T) {
	for _, mode := range []string{"default", "enabled", "cleared"} {
		t.Run(mode, func(t *testing.T) {
			settings := SettingEngine{}
			called := false
			handler := func(_ []byte, _, _ *ice.CandidatePair) bool {
				called = true
				return true
			}
			if mode != "default" {
				settings.SetICECandidatePairPacketHandler(handler)
			}
			if mode == "cleared" {
				settings.SetICECandidatePairPacketHandler(nil)
			}
			if mode == "enabled" {
				require.True(t, settings.iceCandidatePairPacketHandler(nil, nil, nil))
				require.True(t, called)
			} else {
				require.Nil(t, settings.iceCandidatePairPacketHandler)
			}
			gatherer, err := NewAPI(WithSettingEngine(settings)).NewICEGatherer(ICEGatherOptions{})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, gatherer.Close()) })
			require.NoError(t, gatherer.createAgent())
			field := reflect.ValueOf(gatherer.getAgent()).Elem().FieldByName("userCandidatePairPacketHandler")
			require.True(t, field.IsValid())
			require.Equal(t, mode != "enabled", field.IsNil())
			if mode == "enabled" {
				require.Equal(t, reflect.ValueOf(handler).Pointer(), field.Pointer())
			}
		})
	}
}

func TestICEGathererNominationPriorityDefaults(t *testing.T) {
	for _, mode := range []string{"default", "enabled", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			settings := SettingEngine{}
			if mode != "default" {
				settings.SetICEUseCandidateCheckPriority(true)
			}
			if mode == "disabled" {
				settings.SetICEUseCandidateCheckPriority(false)
			}
			gatherer, err := NewAPI(WithSettingEngine(settings)).NewICEGatherer(ICEGatherOptions{})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, gatherer.Close()) })
			require.NoError(t, gatherer.createAgent())
			field := reflect.ValueOf(gatherer.getAgent()).Elem().FieldByName("enableUseCandidateCheckPriority")
			require.True(t, field.IsValid())
			require.Equal(t, mode == "enabled", field.Bool())
		})
	}
}
