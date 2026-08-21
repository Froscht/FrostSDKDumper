#!/usr/bin/env python3
import argparse
import os
import re
import sys
from pathlib import Path

ScriptDir = os.path.dirname(os.path.abspath(__file__))
if ScriptDir not in sys.path:
    sys.path.insert(0, ScriptDir)

from native_from_source import ParseHeader, CollectHighCandidates, TYPE_SIZE

UE_ROOT = "/media/frost/Coding Stuf/Linux/UnrealEngine/Engine/Source"
UE_PLUGINS = "/media/frost/Coding Stuf/Linux/UnrealEngine/Engine/Plugins"
UE_PLUGINS_EXT = "/media/frost/Coding Stuf/Linux/UE_Plugins_External"

RAW_PACKAGE_TO_DIR = {
    "ACLPlugin": [
        f"{UE_PLUGINS}/Animation/ACLPlugin/Source/ACLPlugin/Public",
        f"{UE_PLUGINS}/Animation/ACLPlugin/Source/ACLPlugin/Classes",
    ],
    "AESGCMHandlerComponent": [
        f"{UE_PLUGINS}/Runtime/PacketHandlers/AESGCMHandlerComponent/Source/Public",
    ],
    "Agones": [
        f"{UE_PLUGINS_EXT}/agones/sdks/unreal/Agones/Source/Agones/Public",
        f"{UE_PLUGINS_EXT}/agones/sdks/unreal/Agones/Source/Agones/Classes",
    ],
    "AIModule": [
        f"{UE_ROOT}/Runtime/AIModule/Public",
        f"{UE_ROOT}/Runtime/AIModule/Classes",
    ],
    "ActorLayerUtilities": [
        f"{UE_PLUGINS}/Runtime/ActorLayerUtilities/Source/ActorLayerUtilities/Public",
    ],
    "ActorSequence": [
        f"{UE_PLUGINS}/MovieScene/ActorSequence/Source/ActorSequence/Public",
    ],
    "AdvancedWidgets": [
        f"{UE_ROOT}/Runtime/AdvancedWidgets/Public",
    ],
    "AndroidFileServer": [
        f"{UE_PLUGINS}/Runtime/AndroidFileServer/Source/AndroidFileServer/Public",
        f"{UE_PLUGINS}/Runtime/AndroidFileServer/Source/AndroidFileServer/Classes",
    ],
    "AnimGraphRuntime": [
        f"{UE_ROOT}/Runtime/AnimGraphRuntime/Public",
    ],
    "AnimationBudgetAllocator": [
        f"{UE_PLUGINS}/Runtime/AnimationBudgetAllocator/Source/AnimationBudgetAllocator/Public",
    ],
    "AnimationCore": [
        f"{UE_ROOT}/Runtime/AnimationCore/Public",
    ],
    "AnimationSharing": [
        f"{UE_PLUGINS}/Developer/AnimationSharing/Source/AnimationSharing/Public",
    ],
    "AnimationWarpingRuntime": [
        f"{UE_PLUGINS}/Animation/AnimationWarping/Source/Runtime/Public",
    ],
    "AppleImageUtils": [
        f"{UE_PLUGINS}/Runtime/AppleImageUtils/Source/AppleImageUtils/Public",
    ],
    "ArchVisCharacter": [
        f"{UE_PLUGINS}/Runtime/ArchVisCharacter/Source/ArchVisCharacter/Public",
    ],
    "AssetRegistry": [
        f"{UE_ROOT}/Runtime/AssetRegistry/Public",
        f"{UE_ROOT}/Runtime/AssetRegistry/Internal",
    ],
    "AudioAnalyzer": [
        f"{UE_ROOT}/Runtime/AudioAnalyzer/Public",
        f"{UE_ROOT}/Runtime/AudioAnalyzer/Classes",
    ],
    "AudioCapture": [
        f"{UE_PLUGINS}/Runtime/AudioCapture/Source/AudioCapture/Public",
    ],
    "AudioExtensions": [
        f"{UE_ROOT}/Runtime/AudioExtensions/Public",
    ],
    "AudioGameplay": [
        f"{UE_PLUGINS}/AudioGameplay/Source/AudioGameplay/Public",
    ],
    "AudioGameplayVolume": [
        f"{UE_PLUGINS}/AudioGameplayVolume/Source/AudioGameplayVolume/Public",
    ],
    "AudioLinkCore": [
        f"{UE_ROOT}/Runtime/AudioLink/AudioLinkCore/Public",
    ],
    "AudioLinkEngine": [
        f"{UE_ROOT}/Runtime/AudioLink/AudioLinkEngine/Public",
    ],
    "AudioMixer": [
        f"{UE_ROOT}/Runtime/AudioMixer/Public",
        f"{UE_ROOT}/Runtime/AudioMixer/Classes",
    ],
    "AudioModulation": [
        f"{UE_PLUGINS}/Runtime/AudioModulation/Source/AudioModulation/Public",
    ],
    "AudioPlatformConfiguration": [
        f"{UE_ROOT}/Runtime/AudioPlatformConfiguration/Public",
    ],
    "AudioSynesthesia": [
        f"{UE_PLUGINS}/Runtime/AudioSynesthesia/Source/AudioSynesthesia/Public",
        f"{UE_PLUGINS}/Runtime/AudioSynesthesia/Source/AudioSynesthesia/Classes",
    ],
    "AudioWidgets": [
        f"{UE_PLUGINS}/Runtime/AudioWidgets/Source/AudioWidgets/Public",
    ],
    "AutomationUtils": [
        f"{UE_PLUGINS}/Experimental/AutomationUtils/Source/AutomationUtils/Public",
    ],
    "AvfMediaFactory": [
        f"{UE_PLUGINS}/Media/AvfMedia/Source/AvfMediaFactory/Public",
    ],
    "BinkMediaPlayer": [
        f"{UE_PLUGINS}/Media/BinkMedia/Source/BinkMediaPlayer/Public",
    ],
    "BuildPatchServices": [
        f"{UE_ROOT}/Runtime/Online/BuildPatchServices/Public",
    ],
    "CableComponent": [
        f"{UE_PLUGINS}/Runtime/CableComponent/Source/CableComponent/Classes",
    ],
    "Chaos": [
        f"{UE_ROOT}/Runtime/Experimental/Chaos/Public",
    ],
    "ChaosNiagara": [
        f"{UE_PLUGINS}/Experimental/ChaosNiagara/Source/ChaosNiagara/Public",
        f"{UE_PLUGINS}/Experimental/ChaosNiagara/Source/ChaosNiagara/Classes",
    ],
    "ChaosSolverEngine": [
        f"{UE_ROOT}/Runtime/Experimental/ChaosSolverEngine/Public",
    ],
    "CinematicCamera": [
        f"{UE_ROOT}/Runtime/CinematicCamera/Public",
    ],
    "ClothingSystemRuntimeCommon": [
        f"{UE_ROOT}/Runtime/ClothingSystemRuntimeCommon/Public",
    ],
    "ClothingSystemRuntimeInterface": [
        f"{UE_ROOT}/Runtime/ClothingSystemRuntimeInterface/Public",
    ],
    "ClothingSystemRuntimeNv": [
        f"{UE_ROOT}/Runtime/ClothingSystemRuntimeNv/Public",
    ],
    "CommonInput": [
        f"{UE_PLUGINS}/Runtime/CommonUI/Source/CommonInput/Public",
    ],
    "CommonUI": [
        f"{UE_PLUGINS}/Runtime/CommonUI/Source/CommonUI/Public",
    ],
    "Constraints": [
        f"{UE_ROOT}/Runtime/Experimental/Animation/Constraints/Public",
    ],
    "ControlRig": [
        f"{UE_PLUGINS}/Animation/ControlRig/Source/ControlRig/Public",
    ],
    "CoreOnline": [
        f"{UE_ROOT}/Runtime/CoreOnline/Public",
    ],
    "CoreUObject": [
        f"{UE_ROOT}/Runtime/CoreUObject/Public",
        f"{UE_ROOT}/Runtime/CoreUObject/Internal",
        f"{UE_ROOT}/Runtime/Core/Public",
    ],
    "CustomMeshComponent": [
        f"{UE_PLUGINS}/Runtime/CustomMeshComponent/Source/CustomMeshComponent/Public",
        f"{UE_PLUGINS}/Runtime/CustomMeshComponent/Source/CustomMeshComponent/Classes",
    ],
    "DataRegistry": [
        f"{UE_PLUGINS}/Runtime/DataRegistry/Source/DataRegistry/Public",
    ],
    "DataflowCore": [
        f"{UE_ROOT}/Runtime/Experimental/Dataflow/Core/Public",
    ],
    "DataflowEngine": [
        f"{UE_ROOT}/Runtime/Experimental/Dataflow/Engine/Public",
    ],
    "DataflowEnginePlugin": [
        f"{UE_PLUGINS}/Experimental/Dataflow/Source/DataflowEnginePlugin/Public",
    ],
    "DataflowNodes": [
        f"{UE_PLUGINS}/Experimental/Dataflow/Source/DataflowNodes/Public",
    ],
    "DatasmithContent": [
        f"{UE_PLUGINS}/Enterprise/DatasmithContent/Source/DatasmithContent/Public",
    ],
    "DeveloperSettings": [
        f"{UE_ROOT}/Runtime/DeveloperSettings/Public",
    ],
    "Engine": [
        f"{UE_ROOT}/Runtime/Engine/Public",
        f"{UE_ROOT}/Runtime/Engine/Classes",
        f"{UE_ROOT}/Runtime/Engine/Internal",
    ],
    "EngineMessages": [
        f"{UE_ROOT}/Runtime/EngineMessages/Public",
    ],
    "EngineSettings": [
        f"{UE_ROOT}/Runtime/EngineSettings/Public",
        f"{UE_ROOT}/Runtime/EngineSettings/Classes",
    ],
    "EnhancedInput": [
        f"{UE_PLUGINS}/EnhancedInput/Source/EnhancedInput/Public",
    ],
    "EyeTracker": [
        f"{UE_ROOT}/Runtime/EyeTracker/Public",
    ],
    "FacialAnimation": [
        f"{UE_PLUGINS}/Editor/FacialAnimation/Source/FacialAnimation/Public",
    ],
    "FieldNotification": [
        f"{UE_ROOT}/Runtime/FieldNotification/Public",
    ],
    "FieldSystemEngine": [
        f"{UE_ROOT}/Runtime/Experimental/FieldSystem/Source/FieldSystemEngine/Public",
    ],
    "Foliage": [
        f"{UE_ROOT}/Runtime/Foliage/Public",
    ],
    "FullBodyIK": [
        f"{UE_PLUGINS}/Experimental/FullBodyIK/Source/FullBodyIK/Public",
    ],
    "GLTFExporter": [
        f"{UE_PLUGINS}/Enterprise/GLTFExporter/Source/GLTFExporter/Public",
    ],
    "GameplayAbilities": [
        f"{UE_PLUGINS}/Runtime/GameplayAbilities/Source/GameplayAbilities/Public",
    ],
    "GameplayCameras": [
        f"{UE_PLUGINS}/Cameras/GameplayCameras/Source/GameplayCameras/Public",
    ],
    "GameplayDebugger": [
        f"{UE_ROOT}/Runtime/GameplayDebugger/Public",
    ],
    "GameplayTags": [
        f"{UE_ROOT}/Runtime/GameplayTags/Public",
        f"{UE_ROOT}/Runtime/GameplayTags/Classes",
    ],
    "GameplayTasks": [
        f"{UE_ROOT}/Runtime/GameplayTasks/Public",
        f"{UE_ROOT}/Runtime/GameplayTasks/Classes",
    ],
    "GeometryCache": [
        f"{UE_PLUGINS}/Runtime/GeometryCache/Source/GeometryCache/Public",
        f"{UE_PLUGINS}/Runtime/GeometryCache/Source/GeometryCache/Classes",
    ],
    "GeometryCacheTracks": [
        f"{UE_PLUGINS}/Runtime/GeometryCache/Source/GeometryCacheTracks/Public",
        f"{UE_PLUGINS}/Runtime/GeometryCache/Source/GeometryCacheTracks/Classes",
    ],
    "GeometryCollectionEngine": [
        f"{UE_ROOT}/Runtime/Experimental/GeometryCollectionEngine/Public",
    ],
    "GeometryFramework": [
        f"{UE_ROOT}/Runtime/GeometryFramework/Public",
    ],
    "HeadMountedDisplay": [
        f"{UE_ROOT}/Runtime/HeadMountedDisplay/Public",
    ],
    "HoudiniEngineRuntime": [
        f"{UE_PLUGINS_EXT}/HoudiniEngineForUnreal/Source/HoudiniEngineRuntime/Public",
        f"{UE_PLUGINS_EXT}/HoudiniEngineForUnreal/Source/HoudiniEngineRuntime/Private",
    ],
    "Hotfix": [
        f"{UE_PLUGINS}/Online/OnlineFramework/Source/Hotfix/Public",
    ],
    "HttpNetworkReplayStreaming": [
        f"{UE_ROOT}/Runtime/NetworkReplayStreaming/HttpNetworkReplayStreaming/Public",
    ],
    "IKRig": [
        f"{UE_PLUGINS}/Animation/IKRig/Source/IKRig/Public",
    ],
    "ImageWriteQueue": [
        f"{UE_ROOT}/Runtime/ImageWriteQueue/Public",
    ],
    "ImgMedia": [
        f"{UE_PLUGINS}/Media/ImgMedia/Source/ImgMedia/Public",
        f"{UE_PLUGINS}/Media/ImgMedia/Source/ImgMedia/Internal",
    ],
    "ImgMediaEngine": [
        f"{UE_PLUGINS}/Media/ImgMedia/Source/ImgMediaEngine/Public",
    ],
    "ImgMediaFactory": [
        f"{UE_PLUGINS}/Media/ImgMedia/Source/ImgMediaFactory/Public",
    ],
    "InputCore": [
        f"{UE_ROOT}/Runtime/InputCore/Public",
        f"{UE_ROOT}/Runtime/InputCore/Classes",
    ],
    "InteractiveToolsFramework": [
        f"{UE_ROOT}/Runtime/InteractiveToolsFramework/Public",
    ],
    "InterchangeCommonParser": [
        f"{UE_PLUGINS}/Interchange/Runtime/Source/Parsers/CommonParser/Public",
    ],
    "InterchangeCore": [
        f"{UE_ROOT}/Runtime/Interchange/Core/Public",
    ],
    "InterchangeEngine": [
        f"{UE_ROOT}/Runtime/Interchange/Engine/Public",
    ],
    "InterchangeFactoryNodes": [
        f"{UE_PLUGINS}/Interchange/Runtime/Source/FactoryNodes/Public",
    ],
    "InterchangeImport": [
        f"{UE_PLUGINS}/Interchange/Runtime/Source/Import/Public",
    ],
    "InterchangeMessages": [
        f"{UE_PLUGINS}/Interchange/Runtime/Source/Messages/Public",
    ],
    "InterchangeNodes": [
        f"{UE_PLUGINS}/Interchange/Runtime/Source/Nodes/Public",
    ],
    "InterchangePipelines": [
        f"{UE_PLUGINS}/Interchange/Runtime/Source/Pipelines/Public",
    ],
    "IrisCore": [
        f"{UE_ROOT}/Runtime/Experimental/Iris/Core/Public",
    ],
    "JsonUtilities": [
        f"{UE_ROOT}/Runtime/JsonUtilities/Public",
    ],
    "Landscape": [
        f"{UE_ROOT}/Runtime/Landscape/Public",
        f"{UE_ROOT}/Runtime/Landscape/Classes",
    ],
    "LevelSequence": [
        f"{UE_ROOT}/Runtime/LevelSequence/Public",
    ],
    "Lobby": [
        f"{UE_PLUGINS}/Online/OnlineFramework/Source/Lobby/Public",
    ],
    "LocalFileNetworkReplayStreaming": [
        f"{UE_ROOT}/Runtime/NetworkReplayStreaming/LocalFileNetworkReplayStreaming/Public",
    ],
    "LocalizableMessage": [
        f"{UE_PLUGINS}/Experimental/LocalizableMessage/Source/LocalizableMessage/Public",
    ],
    "LocalizableMessageBlueprint": [
        f"{UE_PLUGINS}/Experimental/LocalizableMessage/Source/LocalizableMessageBlueprint/Public",
    ],
    "LocationServicesBPLibrary": [
        f"{UE_PLUGINS}/Runtime/LocationServicesBPLibrary/Source/LocationServicesBPLibrary/Public",
        f"{UE_PLUGINS}/Runtime/LocationServicesBPLibrary/Source/LocationServicesBPLibrary/Classes",
    ],
    "MaterialShaderQualitySettings": [
        f"{UE_ROOT}/Runtime/MaterialShaderQualitySettings/Classes",
    ],
    "MediaAssets": [
        f"{UE_ROOT}/Runtime/MediaAssets/Public",
    ],
    "MediaCompositing": [
        f"{UE_PLUGINS}/Media/MediaCompositing/Source/MediaCompositing/Public",
    ],
    "MediaPlate": [
        f"{UE_PLUGINS}/Media/MediaPlate/Source/MediaPlate/Public",
    ],
    "MediaUtils": [
        f"{UE_ROOT}/Runtime/MediaUtils/Public",
    ],
    "MeshDescription": [
        f"{UE_ROOT}/Runtime/MeshDescription/Public",
    ],
    "MeshModelingTools": [
        f"{UE_PLUGINS}/Runtime/MeshModelingToolset/Source/MeshModelingTools/Public",
    ],
    "MeshModelingToolsExp": [
        f"{UE_PLUGINS}/Experimental/MeshModelingToolsetExp/Source/MeshModelingToolsExp/Public",
    ],
    "MetasoundEngine": [
        f"{UE_PLUGINS}/Runtime/Metasound/Source/MetasoundEngine/Public",
    ],
    "MetasoundFrontend": [
        f"{UE_PLUGINS}/Runtime/Metasound/Source/MetasoundFrontend/Public",
    ],
    "ModelingComponents": [
        f"{UE_PLUGINS}/Runtime/MeshModelingToolset/Source/ModelingComponents/Public",
    ],
    "ModelingOperators": [
        f"{UE_PLUGINS}/Runtime/MeshModelingToolset/Source/ModelingOperators/Public",
    ],
    "MoviePlayer": [
        f"{UE_ROOT}/Runtime/MoviePlayer/Public",
    ],
    "MovieRenderPipelineCore": [
        f"{UE_PLUGINS}/MovieScene/MovieRenderPipeline/Source/MovieRenderPipelineCore/Public",
    ],
    "MovieRenderPipelineRenderPasses": [
        f"{UE_PLUGINS}/MovieScene/MovieRenderPipeline/Source/MovieRenderPipelineRenderPasses/Public",
    ],
    "MovieRenderPipelineSettings": [
        f"{UE_PLUGINS}/MovieScene/MovieRenderPipeline/Source/MovieRenderPipelineSettings/Public",
    ],
    "MovieScene": [
        f"{UE_ROOT}/Runtime/MovieScene/Public",
    ],
    "MovieSceneCapture": [
        f"{UE_ROOT}/Runtime/MovieSceneCapture/Public",
    ],
    "MovieSceneTracks": [
        f"{UE_ROOT}/Runtime/MovieSceneTracks/Public",
    ],
    "NNE": [
        f"{UE_PLUGINS}/Experimental/NNE/Source/NNE/Public",
        f"{UE_PLUGINS}/Experimental/NNE/Source/NNE/Internal",
    ],
    "NavigationSystem": [
        f"{UE_ROOT}/Runtime/NavigationSystem/Public",
    ],
    "NetCore": [
        f"{UE_ROOT}/Runtime/Net/Core/Public",
        f"{UE_ROOT}/Runtime/Net/Core/Classes",
    ],
    "Niagara": [
        f"{UE_PLUGINS}/FX/Niagara/Source/Niagara/Public",
        f"{UE_PLUGINS}/FX/Niagara/Source/Niagara/Classes",
        f"{UE_PLUGINS}/FX/Niagara/Source/Niagara/Internal",
    ],
    "NiagaraAnimNotifies": [
        f"{UE_PLUGINS}/FX/Niagara/Source/NiagaraAnimNotifies/Public",
    ],
    "NiagaraCore": [
        f"{UE_PLUGINS}/FX/Niagara/Source/NiagaraCore/Public",
    ],
    "NiagaraShader": [
        f"{UE_PLUGINS}/FX/Niagara/Source/NiagaraShader/Public",
    ],
    "OnlineSubsystem": [
        f"{UE_PLUGINS}/Online/OnlineSubsystem/Source/Public",
    ],
    "OnlineSubsystemEOS": [
        f"{UE_PLUGINS}/Online/OnlineSubsystemEOS/Source/OnlineSubsystemEOS/Public",
    ],
    "OnlineSubsystemSteam": [
        f"{UE_PLUGINS}/Online/OnlineSubsystemSteam/Source/Public",
        f"{UE_PLUGINS}/Online/OnlineSubsystemSteam/Source/Classes",
    ],
    "OnlineSubsystemUtils": [
        f"{UE_PLUGINS}/Online/OnlineSubsystemUtils/Source/OnlineSubsystemUtils/Public",
        f"{UE_PLUGINS}/Online/OnlineSubsystemUtils/Source/OnlineSubsystemUtils/Classes",
    ],
    "OodleNetworkHandlerComponent": [
        f"{UE_PLUGINS}/Compression/OodleNetwork/Source/Public",
        f"{UE_PLUGINS}/Compression/OodleNetwork/Source/Classes",
    ],
    "OpenColorIO": [
        f"{UE_PLUGINS}/Compositing/OpenColorIO/Source/OpenColorIO/Public",
    ],
    "Overlay": [
        f"{UE_ROOT}/Runtime/Overlay/Public",
    ],
    "PBIK": [
        f"{UE_PLUGINS}/Experimental/FullBodyIK/Source/PBIK/Public",
    ],
    "PacketHandler": [
        f"{UE_ROOT}/Runtime/PacketHandlers/PacketHandler/Public",
        f"{UE_ROOT}/Runtime/PacketHandlers/PacketHandler/Classes",
    ],
    "Party": [
        f"{UE_PLUGINS}/Online/OnlineFramework/Source/Party/Public",
    ],
    "PhysicsCore": [
        f"{UE_ROOT}/Runtime/PhysicsCore/Public",
    ],
    "ProceduralMeshComponent": [
        f"{UE_PLUGINS}/Runtime/ProceduralMeshComponent/Source/ProceduralMeshComponent/Public",
    ],
    "PropertyPath": [
        f"{UE_ROOT}/Runtime/PropertyPath/Public",
    ],
    "Qos": [
        f"{UE_PLUGINS}/Online/OnlineFramework/Source/Qos/Public",
    ],
    "Rejoin": [
        f"{UE_PLUGINS}/Online/OnlineFramework/Source/Rejoin/Public",
    ],
    "Renderer": [
        f"{UE_ROOT}/Runtime/Renderer/Public",
    ],
    "ReplicationGraph": [
        f"{UE_PLUGINS}/Runtime/ReplicationGraph/Source/Public",
    ],
    "RigVM": [
        f"{UE_PLUGINS}/Runtime/RigVM/Source/RigVM/Public",
    ],
    "SequencerScripting": [
        f"{UE_PLUGINS}/MovieScene/SequencerScripting/Source/SequencerScripting/Public",
    ],
    "Serialization": [
        f"{UE_ROOT}/Runtime/Serialization/Public",
    ],
    "SessionMessages": [
        f"{UE_ROOT}/Runtime/SessionMessages/Public",
    ],
    "SignificanceManager": [
        f"{UE_PLUGINS}/Runtime/SignificanceManager/Source/SignificanceManager/Public",
    ],
    "Slate": [
        f"{UE_ROOT}/Runtime/Slate/Public",
    ],
    "SlateCore": [
        f"{UE_ROOT}/Runtime/SlateCore/Public",
    ],
    "SocketSubsystemEOS": [
        f"{UE_PLUGINS}/Online/SocketSubsystemEOS/Source/SocketSubsystemEOS/Public",
    ],
    "SoundFields": [
        f"{UE_PLUGINS}/Runtime/SoundFields/Source/SoundFields/Public",
    ],
    "SoundUtilities": [
        f"{UE_PLUGINS}/Runtime/SoundUtilities/Source/SoundUtilities/Public",
    ],
    "Spatialization": [
        f"{UE_PLUGINS}/Runtime/Spatialization/Source/Spatialization/Public",
    ],
    "StaticMeshDescription": [
        f"{UE_ROOT}/Runtime/StaticMeshDescription/Public",
    ],
    "StructUtils": [
        f"{UE_PLUGINS}/Experimental/StructUtils/Source/StructUtils/Public",
    ],
    "StructUtilsEngine": [
        f"{UE_PLUGINS}/Experimental/StructUtils/Source/StructUtilsEngine/Public",
    ],
    "Synthesis": [
        f"{UE_PLUGINS}/Runtime/Synthesis/Source/Synthesis/Public",
        f"{UE_PLUGINS}/Runtime/Synthesis/Source/Synthesis/Classes",
    ],
    "TcpMessaging": [
        f"{UE_PLUGINS}/Messaging/TcpMessaging/Source/TcpMessaging/Public",
    ],
    "TemplateSequence": [
        f"{UE_PLUGINS}/MovieScene/TemplateSequence/Source/TemplateSequence/Public",
    ],
    "Text3D": [
        f"{UE_PLUGINS}/Experimental/Text3D/Source/Text3D/Public",
    ],
    "TimeManagement": [
        f"{UE_ROOT}/Runtime/TimeManagement/Public",
    ],
    "TraceUtilities": [
        f"{UE_PLUGINS}/TraceUtilities/Source/TraceUtilities/Public",
    ],
    "TypedElementFramework": [
        f"{UE_ROOT}/Runtime/TypedElementFramework/Public",
    ],
    "TypedElementRuntime": [
        f"{UE_ROOT}/Runtime/TypedElementRuntime/Public",
    ],
    "UMG": [
        f"{UE_ROOT}/Runtime/UMG/Public",
    ],
    "UdpMessaging": [
        f"{UE_PLUGINS}/Messaging/UdpMessaging/Source/UdpMessaging/Public",
    ],
    "VariantManagerContent": [
        f"{UE_PLUGINS}/Enterprise/VariantManagerContent/Source/VariantManagerContent/Public",
    ],
    "VectorVM": [
        f"{UE_ROOT}/Runtime/VectorVM/Public",
    ],
    "WaveTable": [
        f"{UE_PLUGINS}/Runtime/WaveTable/Source/WaveTable/Public",
    ],
    "WebSocketNetworking": [
        f"{UE_PLUGINS}/Experimental/WebSocketNetworking/Source/WebSocketNetworking/Public",
    ],
    "WidgetCarousel": [
        f"{UE_ROOT}/Runtime/WidgetCarousel/Public",
    ],
    "WinDualShock": [
        f"{UE_PLUGINS}/Runtime/Windows/WinDualShock/Source/WinDualShock/Public",
    ],
    "WmfMediaFactory": [
        f"{UE_PLUGINS}/Media/WmfMedia/Source/WmfMediaFactory/Public",
    ],
}


def BuildPackageToDir():
    Mapping = {}
    for Pkg, Dirs in RAW_PACKAGE_TO_DIR.items():
        Keep = [D for D in Dirs if os.path.isdir(D)]
        if Keep:
            Mapping[Pkg] = Keep
    return Mapping


def BuildHeaderIndex(PackageToDir):
    Index = {}
    Cache = {}
    for Pkg, Dirs in PackageToDir.items():
        for D in Dirs:
            if D in Cache:
                continue
            Files = []
            for Root, _, Names in os.walk(D):
                for N in Names:
                    if N.endswith(".h"):
                        Files.append((N, os.path.join(Root, N)))
            Cache[D] = Files
        Bucket = Index.setdefault(Pkg, {})
        for D in Dirs:
            for N, P in Cache[D]:
                Bucket.setdefault(N, []).append(P)
    return Index


def LocateHeader(HeaderIndex, Package, SdkClassName):
    Bucket = HeaderIndex.get(Package)
    if not Bucket:
        return None
    Names = [SdkClassName]
    if SdkClassName and SdkClassName[0].isupper() and SdkClassName[0] not in ("A", "U", "F", "T", "S", "I", "E"):
        Names.append("A" + SdkClassName)
    for Prefix in ("A", "U", "F"):
        Candidate = Prefix + SdkClassName
        if Candidate not in Names:
            Names.append(Candidate)
    for N in Names:
        Key = N + ".h"
        Paths = Bucket.get(Key)
        if Paths:
            return Paths[0]
    return None


BlockCommentRe = re.compile(
    r"^//\s+(?P<kind>Class|Struct)\s+(?P<path>/[^\s]+)\s*$"
)

NamespaceRe = re.compile(
    r"^namespace\s+(?P<name>[A-Za-z_][\w]*)\s*\{"
)


def FindBlocks(Text):
    Lines = Text.split("\n")
    LineStarts = []
    Cursor = 0
    for Line in Lines:
        LineStarts.append(Cursor)
        Cursor += len(Line) + 1

    Blocks = []
    LineCount = len(Lines)
    Idx = 0
    while Idx < LineCount:
        Line = Lines[Idx]
        NsMatch = NamespaceRe.match(Line)
        if not NsMatch:
            Idx += 1
            continue
        NsName = NsMatch.group("name")
        Look = Idx - 1
        Kind = None
        ObjPath = None
        while Look >= 0 and Look >= Idx - 40:
            L = Lines[Look]
            if not L.startswith("//"):
                break
            CM = BlockCommentRe.match(L)
            if CM:
                Kind = CM.group("kind")
                ObjPath = CM.group("path")
                break
            Look -= 1
        if Kind is None or ObjPath is None:
            Idx += 1
            continue

        Depth = 0
        for Ch in Line:
            if Ch == "{":
                Depth += 1
            elif Ch == "}":
                Depth -= 1
        EndIdx = Idx + 1
        while EndIdx < LineCount and Depth > 0:
            EL = Lines[EndIdx]
            for Ch in EL:
                if Ch == "{":
                    Depth += 1
                elif Ch == "}":
                    Depth -= 1
                    if Depth == 0:
                        break
            EndIdx += 1
        if Depth != 0:
            Idx += 1
            continue

        BodyStart = LineStarts[Idx] + len(Line) + 1
        BodyEnd = LineStarts[EndIdx - 1]
        Blocks.append({
            "kind": Kind,
            "path": ObjPath,
            "namespace": NsName,
            "body_start": BodyStart,
            "body_end": BodyEnd,
            "line_start": Idx,
            "line_end": EndIdx,
        })
        Idx = EndIdx
    return Blocks


BodyEntryRe = re.compile(
    r"constexpr\s+uint32_t\s+(\w+)\s*=\s*(0x[0-9a-fA-F]+);"
    r"\s*//\s*([^/]+?)\s*//\s*"
    r"(?:mask=(0x[0-9a-fA-F]+)\s*//\s*)?"
    r"size=(0x[0-9a-fA-F]+)"
    r"(?:\s*//\s*(native))?"
)


def ParseSdkBody(Body):
    Reflected = []
    Natives = []
    for M in BodyEntryRe.finditer(Body):
        Name = M.group(1)
        Offset = int(M.group(2), 16)
        TypeStr = M.group(3).strip()
        Mask = int(M.group(4), 16) if M.group(4) else 0
        Size = int(M.group(5), 16)
        IsNative = M.group(6) == "native"
        Entry = {
            "name": Name,
            "offset": Offset,
            "type": TypeStr,
            "mask": Mask,
            "size": Size,
        }
        if IsNative:
            Natives.append(Entry)
        else:
            Reflected.append(Entry)
    return {
        "reflected": Reflected,
        "natives": Natives,
        "native_bits": [N for N in Natives if N["mask"] > 0],
    }


LineRewriteRe = re.compile(
    r"constexpr\s+uint32_t\s+Native_0x[0-9a-fA-F]+(?:_bit\d+)?(?:_\w+)?\s*=\s*"
    r"(?P<off>0x[0-9a-fA-F]+);\s*//[^\n]*?"
    r"(?:mask=(?P<mask>0x[0-9a-fA-F]+)\s*//[^\n]*?)?"
    r"size=0x[0-9a-fA-F]+[^\n]*\n"
)


def RewriteBody(Body, Candidates):
    Applied = 0

    def _Sub(Mo):
        nonlocal Applied
        Line = Mo.group(0)
        Off = int(Mo.group("off"), 16)
        MaskStr = Mo.group("mask")
        Mask = int(MaskStr, 16) if MaskStr else 0
        Key = (Off, Mask)
        if Key not in Candidates:
            return Line
        NewName = Candidates[Key]
        if Mask:
            BitIdx = Mask.bit_length() - 1
            NewIdent = f"Native_0x{Off:x}_bit{BitIdx}_{NewName}"
        else:
            NewIdent = f"Native_0x{Off:x}_{NewName}"
        Line = re.sub(
            r"Native_0x[0-9a-fA-F]+(?:_bit\d+)?(?:_\w+)?",
            NewIdent,
            Line,
            count=1,
        )
        if "// source-candidate" not in Line:
            Stripped = Line.rstrip("\n")
            Line = Stripped + f"  // source-candidate={NewName}\n"
        elif not Line.endswith("\n"):
            Line += "\n"
        Applied += 1
        return Line

    NewBody = LineRewriteRe.sub(_Sub, Body)
    return NewBody, Applied


ScriptPathRe = re.compile(r"^/Script/(?P<pkg>[^./]+)\.(?P<name>[A-Za-z_][\w]*)")


def PackageFromPath(ObjPath):
    M = ScriptPathRe.match(ObjPath)
    if not M:
        return None, None
    return M.group("pkg"), M.group("name")


def Main():
    Ap = argparse.ArgumentParser()
    ProjectRoot = os.path.dirname(ScriptDir)
    DefaultWithNames = os.path.join(ProjectRoot, "SDK_Output.txt.with_names")
    DefaultRaw = os.path.join(ProjectRoot, "SDK_Output.txt")
    Ap.add_argument("--sdk", default=None,
                    help="Input SDK path (default: SDK_Output.txt.with_names if present, else SDK_Output.txt)")
    Ap.add_argument("--out", default=DefaultWithNames,
                    help="Output SDK path (default: SDK_Output.txt.with_names)")
    Ap.add_argument("--verbose", "-v", action="store_true")
    Args = Ap.parse_args()

    Sdk = Args.sdk
    if not Sdk:
        if os.path.isfile(DefaultWithNames):
            Sdk = DefaultWithNames
        elif os.path.isfile(DefaultRaw):
            Sdk = DefaultRaw
        else:
            print("no SDK_Output.txt or .with_names found in project root", file=sys.stderr)
            sys.exit(1)

    print(f"input:  {Sdk}")
    print(f"output: {Args.out}")

    PackageToDir = BuildPackageToDir()
    print(f"usable UE modules: {len(PackageToDir)} of {len(RAW_PACKAGE_TO_DIR)}")
    for Pkg in sorted(RAW_PACKAGE_TO_DIR):
        if Pkg not in PackageToDir:
            print(f"  warning: no source dirs found for package {Pkg} — skipped")

    print("indexing UE headers...")
    HeaderIndex = BuildHeaderIndex(PackageToDir)
    TotalHeaders = sum(sum(len(V) for V in B.values()) for B in HeaderIndex.values())
    print(f"indexed {TotalHeaders} .h files across {len(HeaderIndex)} packages")

    with open(Sdk, "r", encoding="utf-8", errors="replace") as F:
        Text = F.read()

    print("scanning SDK for namespace blocks...")
    Blocks = FindBlocks(Text)
    print(f"found {len(Blocks)} namespace blocks")

    Stats = {
        "total": len(Blocks),
        "considered": 0,
        "no_script_prefix": 0,
        "unmapped_package": 0,
        "no_native": 0,
        "no_header": 0,
        "header_parse_empty": 0,
        "no_candidates": 0,
        "with_candidates": 0,
        "candidates_total": 0,
        "lines_rewritten": 0,
    }
    PerClassCands = []
    ProcessedCands = {}
    ClassBlockLookup = {}
    for B in Blocks:
        if B["kind"] not in ("Class", "Struct"):
            continue
        Stats["considered"] += 1
        Package, ClassName = PackageFromPath(B["path"])
        if not Package:
            Stats["no_script_prefix"] += 1
            continue
        if Package not in PackageToDir:
            Stats["unmapped_package"] += 1
            continue
        BodyText = Text[B["body_start"]:B["body_end"]]
        if "Native_0x" not in BodyText:
            Stats["no_native"] += 1
            continue

        HeaderPath = LocateHeader(HeaderIndex, Package, ClassName)
        if not HeaderPath:
            if Args.verbose:
                print(f"  no header for {Package}.{ClassName}")
            Stats["no_header"] += 1
            continue

        try:
            Fields = ParseHeader(HeaderPath, ClassName)
        except Exception as E:
            print(f"  parse fail {HeaderPath} ({ClassName}): {E}", file=sys.stderr)
            Stats["header_parse_empty"] += 1
            continue
        if not Fields:
            Stats["header_parse_empty"] += 1
            continue

        SdkData = ParseSdkBody(BodyText)
        Cands = CollectHighCandidates(Fields, SdkData)
        if not Cands:
            Stats["no_candidates"] += 1
            continue

        Stats["with_candidates"] += 1
        Stats["candidates_total"] += len(Cands)
        PerClassCands.append((ClassName, Package, len(Cands)))
        ProcessedCands[id(B)] = Cands
        ClassBlockLookup[id(B)] = B

    print(f"classes/structs considered:        {Stats['considered']}")
    print(f"  skipped (non /Script prefix):    {Stats['no_script_prefix']}")
    print(f"  skipped (unmapped package):      {Stats['unmapped_package']}")
    print(f"  skipped (no Native_ entries):    {Stats['no_native']}")
    print(f"  skipped (header not found):      {Stats['no_header']}")
    print(f"  skipped (empty header parse):    {Stats['header_parse_empty']}")
    print(f"  produced 0 candidates:           {Stats['no_candidates']}")
    print(f"  produced candidates:             {Stats['with_candidates']}")
    print(f"total candidates:                  {Stats['candidates_total']}")

    if not ProcessedCands:
        print("nothing to inject — writing input through to output unchanged")
        if Sdk != Args.out:
            with open(Args.out, "w", encoding="utf-8") as F:
                F.write(Text)
        return

    Pieces = []
    Cursor = 0
    OrderedBlocks = sorted(
        (ClassBlockLookup[K] for K in ProcessedCands),
        key=lambda B: B["body_start"],
    )
    for B in OrderedBlocks:
        Cands = ProcessedCands[id(B)]
        BodyText = Text[B["body_start"]:B["body_end"]]
        NewBody, Applied = RewriteBody(BodyText, Cands)
        Stats["lines_rewritten"] += Applied
        Pieces.append(Text[Cursor:B["body_start"]])
        Pieces.append(NewBody)
        Cursor = B["body_end"]
    Pieces.append(Text[Cursor:])
    NewText = "".join(Pieces)

    with open(Args.out, "w", encoding="utf-8") as F:
        F.write(NewText)
    print(f"lines rewritten:                   {Stats['lines_rewritten']}")
    print(f"wrote {Args.out}")

    PerClassCands.sort(key=lambda T: T[2], reverse=True)
    print("\ntop 15 classes by candidate count:")
    for ClassName, Package, Count in PerClassCands[:15]:
        print(f"  {Count:5d}  {Package}.{ClassName}")


if __name__ == "__main__":
    Main()
